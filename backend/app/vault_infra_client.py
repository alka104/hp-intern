"""
vault_infra_client.py — Infrastructure credential rotation using
Vault's Database Secrets Engine (Phase 2) and KV secrets (Phase 5).

Phase 2: Dynamic PostgreSQL credentials via Vault database engine.
Phase 5: Kafka credentials stored in Vault KV, rotated on CRITICAL_ALERT,
         kafka_client.reconnect_kafka() called immediately after rotation.

Services and their rotation mechanism:
  elasticsearch → Vault database engine (dynamic DB user, TTL=1h)
  database      → Vault database engine (dynamic DB user, TTL=1h)
  kafka         → Vault KV secret rotation + kafka_client reconnect
  readonly      → Vault database engine (dynamic DB user, TTL=30m)
"""

import logging
import uuid
import secrets as secrets_mod
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import hvac

from app.config import VAULT_ADDR, VAULT_TOKEN

logger = logging.getLogger("hpe.vault_infra")

_client: Optional[hvac.Client] = None
_connected = False

# In-memory lease tracker for database engine credentials
_active_leases: Dict[str, Dict[str, Any]] = {}

_infra_rotation_count = 0


def connect(vault_client_instance: hvac.Client) -> bool:
    """
    Reuse the already-authenticated hvac client from vault_client.py.
    Called from main.py after vault_client.connect_vault() succeeds.
    """
    global _client, _connected
    try:
        _client = vault_client_instance
        if _client.is_authenticated():
            logger.info("Vault infra client ready (database secrets engine)")
            _connected = True
            return True
        else:
            logger.error("Vault infra client: authentication check failed")
            _connected = False
            return False
    except Exception as e:
        logger.error(f"Vault infra client connection failed: {e}")
        _connected = False
        return False


def is_connected() -> bool:
    return _connected


def get_dynamic_credential(service: str) -> Dict[str, Any]:
    """
    Ask Vault to generate a brand-new PostgreSQL credential on the fly.
    Used for: elasticsearch, database, readonly services.
    Vault connects to PostgreSQL, runs CREATE ROLE, returns temp creds.
    """
    if not _client or not _connected:
        return {"success": False, "error": "Vault infra client not connected"}

    role_map = {
        "backend":       "hpe-backend-role",
        "database":      "hpe-backend-role",
        "elasticsearch": "hpe-backend-role",
        "readonly":      "hpe-readonly-role",
    }
    role = role_map.get(service, "hpe-backend-role")

    try:
        response = _client.secrets.database.generate_credentials(name=role)

        username = response["data"]["username"]
        password = response["data"]["password"]
        lease_id = response["lease_id"]
        lease_duration = response["lease_duration"]
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=lease_duration)

        logger.info(
            f"[INFRA] Dynamic credential issued for '{service}' "
            f"→ user='{username}' lease='{lease_id}' TTL={lease_duration}s"
        )

        return {
            "success": True,
            "service": service,
            "username": username,
            "password": password,
            "lease_id": lease_id,
            "lease_duration": lease_duration,
            "expires_at": expires_at.isoformat(),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "mechanism": "vault_database_engine",
        }

    except Exception as e:
        logger.error(f"[INFRA] Failed to generate dynamic credential for '{service}': {e}")
        return {"success": False, "error": str(e), "service": service}


def _rotate_kafka_credential() -> Dict[str, Any]:
    """
    Phase 5: Rotate Kafka credentials in Vault KV.
    Generates a new password, updates secret/hpe/kafka/credentials,
    then calls kafka_client.reconnect_kafka() to rebuild clients.
    """
    try:
        # Read current credential
        current_data = {}
        try:
            response = _client.secrets.kv.v2.read_secret_version(
                path="hpe/kafka/credentials",
                raise_on_deleted_version=False,
            )
            current_data = response.get("data", {}).get("data", {})
        except Exception:
            pass

        old_username = current_data.get("username", "hpe-kafka-producer")
        rotation_count = current_data.get("rotation_count", 0) + 1

        # Generate new password — username stays the same (service account)
        new_password = f"hpe-kafka-rotated-{secrets_mod.token_hex(20)}"

        new_creds = {
            "username": old_username,
            "password": new_password,
            "broker": current_data.get("broker", "kafka:9092"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rotation_count": rotation_count,
            "description": (
                "Kafka service account — rotated by vault_infra_client "
                "on CRITICAL_ALERT admin approval."
            ),
        }

        _client.secrets.kv.v2.create_or_update_secret(
            path="hpe/kafka/credentials",
            secret=new_creds,
        )

        logger.warning(
            f"[INFRA] Kafka credentials rotated in Vault "
            f"(user='{old_username}', rotation_count={rotation_count})"
        )

        # Immediately reconnect Kafka clients with new credentials
        try:
            from app import kafka_client
            reconnect_success = kafka_client.reconnect_kafka()
            logger.warning(
                f"[INFRA] Kafka reconnect after rotation: "
                f"{'success' if reconnect_success else 'FAILED'}"
            )
        except Exception as reconnect_err:
            logger.error(f"[INFRA] Kafka reconnect error: {reconnect_err}")
            reconnect_success = False

        return {
            "success": True,
            "mechanism": "vault_kv_rotation",
            "username": old_username,
            "rotation_count": rotation_count,
            "kafka_reconnected": reconnect_success,
            "vault_path": "secret/hpe/kafka/credentials",
            "rotated_at": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"[INFRA] Kafka credential rotation failed: {e}")
        return {"success": False, "error": str(e), "mechanism": "vault_kv_rotation"}


def rotate_infrastructure_credentials(
    service: str,
    reason: str = "admin_approved_critical_threat",
    threat_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Called by routes/admin.py when admin approves a CRITICAL_ALERT.

    Routing:
      kafka        → _rotate_kafka_credential() — KV rotation + reconnect
      elasticsearch, database, readonly → get_dynamic_credential() — DB engine
    """
    global _infra_rotation_count

    if not _client or not _connected:
        return {"success": False, "error": "Vault infra client not connected"}

    rotation_id = str(uuid.uuid4())
    rotation_start = datetime.now(timezone.utc)

    logger.warning(
        f"[INFRA] Infrastructure rotation triggered — "
        f"service='{service}' reason='{reason}' score={threat_score:.4f}"
    )

    # ── Kafka: KV rotation + reconnect (Phase 5) ──────────────────────────────
    if service == "kafka":
        result = _rotate_kafka_credential()
        _infra_rotation_count += 1
        latency_ms = (datetime.now(timezone.utc) - rotation_start).total_seconds() * 1000

        return {
            "success": result.get("success", False),
            "rotation_id": rotation_id,
            "rotation_number": _infra_rotation_count,
            "service": service,
            "reason": reason,
            "threat_score": threat_score,
            "timestamp": rotation_start.isoformat(),
            "latency_ms": round(latency_ms, 2),
            "new_credential": {
                "username": result.get("username", ""),
                "mechanism": result.get("mechanism", "vault_kv_rotation"),
                "rotation_count": result.get("rotation_count", 0),
                "kafka_reconnected": result.get("kafka_reconnected", False),
            },
            "revocation": {
                "revoked": True,
                "note": "Previous Kafka password invalidated in Vault KV",
            },
        }

    # ── Database engine services: dynamic credentials ─────────────────────────
    revocation_result = {"revoked": False, "previous_lease": None}
    if service in _active_leases:
        current = _active_leases[service]
        old_lease_id = current.get("lease_id")
        old_username = current.get("username")
        try:
            _client.sys.revoke_lease(lease_id=old_lease_id)
            revocation_result = {
                "revoked": True,
                "previous_lease": old_lease_id,
                "previous_username": old_username,
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            }
            logger.info(
                f"[INFRA] Revoked lease '{old_lease_id}' "
                f"(DB user '{old_username}' deleted from PostgreSQL)"
            )
        except Exception as e:
            logger.warning(f"[INFRA] Lease revocation warning: {e}")
            revocation_result = {"revoked": False, "error": str(e)}

    new_creds = get_dynamic_credential(service)

    if not new_creds.get("success"):
        return {
            "success": False,
            "rotation_id": rotation_id,
            "service": service,
            "error": new_creds.get("error"),
            "revocation": revocation_result,
        }

    _active_leases[service] = {
        "lease_id":        new_creds["lease_id"],
        "username":        new_creds["username"],
        "issued_at":       new_creds["issued_at"],
        "expires_at":      new_creds["expires_at"],
        "rotation_reason": reason,
    }

    _infra_rotation_count += 1
    latency_ms = (datetime.now(timezone.utc) - rotation_start).total_seconds() * 1000

    logger.warning(
        f"[INFRA] Rotation complete — service='{service}' "
        f"new_user='{new_creds['username']}' "
        f"TTL={new_creds['lease_duration']}s "
        f"rotation_#{_infra_rotation_count}"
    )

    return {
        "success": True,
        "rotation_id": rotation_id,
        "rotation_number": _infra_rotation_count,
        "service": service,
        "reason": reason,
        "threat_score": threat_score,
        "timestamp": rotation_start.isoformat(),
        "latency_ms": round(latency_ms, 2),
        "new_credential": {
            "username":               new_creds["username"],
            "lease_id":               new_creds["lease_id"],
            "lease_duration_seconds": new_creds["lease_duration"],
            "expires_at":             new_creds["expires_at"],
            "mechanism":              new_creds["mechanism"],
        },
        "revocation": revocation_result,
    }


def get_active_leases() -> Dict[str, Any]:
    """
    Returns metadata about all currently active infrastructure leases.
    Includes both database engine leases and Kafka KV credential status.
    """
    result = {}
    now = datetime.now(timezone.utc)

    # Database engine leases
    for service, lease in _active_leases.items():
        expires_str = lease.get("expires_at", "")
        try:
            expires_dt = datetime.fromisoformat(expires_str)
            seconds_remaining = int((expires_dt - now).total_seconds())
        except Exception:
            seconds_remaining = -1

        result[service] = {
            "username":          lease.get("username"),
            "lease_id":          lease.get("lease_id"),
            "issued_at":         lease.get("issued_at"),
            "expires_at":        expires_str,
            "seconds_remaining": max(seconds_remaining, 0),
            "expired":           seconds_remaining <= 0,
            "rotation_reason":   lease.get("rotation_reason", "initial"),
            "mechanism":         "vault_database_engine",
        }

    # Phase 5: Kafka KV credential status
    try:
        from app import kafka_client
        kafka_info = kafka_client.get_active_credential_info()
        result["kafka"] = {
            **kafka_info,
            "mechanism": "vault_kv",
            "rotation_reason": _active_leases.get("kafka", {}).get("rotation_reason", "initial"),
        }
    except Exception:
        pass

    return result


def get_infra_rotation_count() -> int:
    return _infra_rotation_count