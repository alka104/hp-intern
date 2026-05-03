"""
vault_infra_client.py — Infrastructure credential rotation using
Vault's Database Secrets Engine (Phase 2).

Unlike vault_client.py which manages static KV credentials per user,
this module uses Vault's database engine to generate DYNAMIC credentials:
  - Vault talks directly to PostgreSQL
  - Creates a brand-new DB service user on every request
  - That user auto-expires after TTL (1h for backend, 30m for readonly)
  - On admin approval of CRITICAL threat: current lease revoked immediately,
    new one issued — the old DB user is deleted from PostgreSQL instantly

No static password ever sits in Vault KV store for infra credentials.
Called from routes/admin.py when admin approves a CRITICAL_ALERT.
"""

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import hvac

from app.config import VAULT_ADDR, VAULT_TOKEN

logger = logging.getLogger("hpe.vault_infra")

_client: Optional[hvac.Client] = None
_connected = False

# ── In-memory lease tracker ───────────────────────────────────────────────────
# Tracks the currently active Vault lease per service.
# { "service_name": { lease_id, username, issued_at, expires_at } }
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

    Vault connects to PostgreSQL as vault-root, runs CREATE ROLE SQL,
    and returns a temporary username + password that expires after TTL.
    The credential is never stored anywhere — it exists only in the DB
    and in memory here until the lease expires or is revoked.

    service: 'backend' (read/write, TTL=1h) or 'readonly' (TTL=30m)
             Also accepts 'elasticsearch', 'kafka', 'database' — all
             map to hpe-backend-role for now.
    """
    if not _client or not _connected:
        return {"success": False, "error": "Vault infra client not connected"}

    role_map = {
        "backend":       "hpe-backend-role",
        "database":      "hpe-backend-role",
        "elasticsearch": "hpe-backend-role",
        "kafka":         "hpe-backend-role",
        "readonly":      "hpe-readonly-role",
    }
    role = role_map.get(service, "hpe-backend-role")

    try:
        # Vault talks to PostgreSQL, creates a temp user, returns creds
        response = _client.secrets.database.generate_credentials(name=role)

        username = response["data"]["username"]
        password = response["data"]["password"]
        lease_id = response["lease_id"]
        lease_duration = response["lease_duration"]  # seconds
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
        }

    except Exception as e:
        logger.error(f"[INFRA] Failed to generate dynamic credential for '{service}': {e}")
        return {"success": False, "error": str(e), "service": service}


def rotate_infrastructure_credentials(
    service: str,
    reason: str = "admin_approved_critical_threat",
    threat_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Called by routes/admin.py when admin approves a CRITICAL_ALERT.

    Steps:
    1. Immediately revoke the current active lease for this service
       (Vault tells PostgreSQL to DROP ROLE — user deleted instantly)
    2. Issue a brand-new dynamic credential from Vault
    3. Update the in-memory lease tracker

    This is infrastructure-level rotation, complementing the user-level
    rotation in vault_client.py. Both fire on CRITICAL_ALERT approval:
      - vault_client.rotate_credentials(user=...)  → user KV secret updated
      - rotate_infrastructure_credentials(service=...) → DB service user replaced
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

    # ── Step 1: Revoke current lease ──────────────────────────────────────────
    revocation_result = {"revoked": False, "previous_lease": None}
    if service in _active_leases:
        current = _active_leases[service]
        old_lease_id = current.get("lease_id")
        old_username = current.get("username")
        try:
            # Vault immediately tells PostgreSQL: DROP ROLE "old_username"
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
            logger.warning(f"[INFRA] Lease revocation warning (may have already expired): {e}")
            revocation_result = {"revoked": False, "error": str(e)}

    # ── Step 2: Issue new dynamic credential ─────────────────────────────────
    new_creds = get_dynamic_credential(service)

    if not new_creds.get("success"):
        return {
            "success": False,
            "rotation_id": rotation_id,
            "service": service,
            "error": new_creds.get("error"),
            "revocation": revocation_result,
        }

    # ── Step 3: Update lease tracker ─────────────────────────────────────────
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
            # password intentionally omitted from rotation result
            "lease_id":               new_creds["lease_id"],
            "lease_duration_seconds": new_creds["lease_duration"],
            "expires_at":             new_creds["expires_at"],
        },
        "revocation": revocation_result,
    }


def get_active_leases() -> Dict[str, Any]:
    """
    Returns metadata about all currently active infrastructure leases.
    Used by /api/health and admin dashboard.
    Passwords are never included — only lease IDs, usernames, TTL.
    """
    result = {}
    now = datetime.now(timezone.utc)
    for service, lease in _active_leases.items():
        expires_str = lease.get("expires_at", "")
        try:
            expires_dt = datetime.fromisoformat(expires_str)
            seconds_remaining = int((expires_dt - now).total_seconds())
        except Exception:
            seconds_remaining = -1

        result[service] = {
            "username":         lease.get("username"),
            "lease_id":         lease.get("lease_id"),
            "issued_at":        lease.get("issued_at"),
            "expires_at":       expires_str,
            "seconds_remaining": max(seconds_remaining, 0),
            "expired":          seconds_remaining <= 0,
            "rotation_reason":  lease.get("rotation_reason", "initial"),
        }
    return result


def get_infra_rotation_count() -> int:
    return _infra_rotation_count