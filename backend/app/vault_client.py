"""
vault_client.py — Real HashiCorp Vault client for credential management.
Phase 3: Switched from root token auth to AppRole auth.
  - Reads role_id + secret_id from /vault/data/.approle_credentials
  - Exchanges them for a short-lived token (TTL=1h)
  - Background thread renews the token every 45 minutes
  - If AppRole creds not found, falls back to VAULT_TOKEN for local dev
"""

import json
import logging
import uuid
import secrets
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

import hvac

from app.config import (
    VAULT_ADDR, VAULT_TOKEN, VAULT_SECRETS_PATH,
    PROFILES_PATH, VAULT_APPROLE_CREDS_FILE
)

logger = logging.getLogger("hpe.vault")

_client: Optional[hvac.Client] = None
_connected = False
_rotation_count = 0
_user_profiles: List[Dict[str, Any]] = []

# Phase 3 — token renewal tracking
_token_renewal_thread: Optional[threading.Thread] = None
_renewal_stop_event = threading.Event()
_auth_method = "unknown"   # "approle" or "token" — logged on startup


# ── Phase 3: AppRole credential loader ───────────────────────────────────────

def _load_approle_credentials() -> Optional[Dict[str, str]]:
    """
    Read role_id and secret_id from the file written by vault-init.
    The vault_data volume is mounted read-only into the backend container
    at /vault/data, so both containers share this file.
    Returns {"role_id": "...", "secret_id": "..."} or None if not found.
    """
    creds_path = Path(VAULT_APPROLE_CREDS_FILE)
    if not creds_path.exists():
        logger.warning(
            f"AppRole credentials file not found at {VAULT_APPROLE_CREDS_FILE}. "
            f"Falling back to VAULT_TOKEN if set."
        )
        return None

    try:
        creds = {}
        with open(creds_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    creds[key.strip()] = value.strip()

        role_id = creds.get("VAULT_ROLE_ID", "")
        secret_id = creds.get("VAULT_SECRET_ID", "")

        if not role_id or not secret_id:
            logger.warning("AppRole credentials file exists but role_id or secret_id is empty.")
            return None

        logger.info(f"AppRole credentials loaded from {VAULT_APPROLE_CREDS_FILE}")
        return {"role_id": role_id, "secret_id": secret_id}

    except Exception as e:
        logger.error(f"Failed to read AppRole credentials file: {e}")
        return None


def _authenticate_approle(role_id: str, secret_id: str) -> Optional[str]:
    """
    Exchange role_id + secret_id for a short-lived Vault token.
    Returns the token string or None on failure.
    """
    try:
        unauthenticated_client = hvac.Client(url=VAULT_ADDR)
        response = unauthenticated_client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id,
        )
        token = response["auth"]["client_token"]
        ttl = response["auth"]["lease_duration"]
        logger.info(
            f"AppRole authentication successful. "
            f"Token TTL={ttl}s ({ttl // 60}m). Will renew every 45m."
        )
        return token
    except Exception as e:
        logger.error(f"AppRole authentication failed: {e}")
        return None


def _start_token_renewal(role_id: str, secret_id: str):
    """
    Background thread that renews the Vault token every 45 minutes.
    Token TTL is 1h — renewal at 45m gives a 15-minute safety margin.
    If renewal fails, re-authenticates from scratch using role_id + secret_id.
    """
    global _token_renewal_thread, _renewal_stop_event

    _renewal_stop_event.clear()

    def _renewal_loop():
        while not _renewal_stop_event.wait(timeout=45 * 60):  # wait 45 minutes
            if not _client:
                continue
            try:
                # Try renew-self first (fastest path)
                _client.auth.token.renew_self()
                logger.info("[Vault] Token renewed successfully (renew-self)")
            except Exception as renew_err:
                logger.warning(f"[Vault] Token renewal failed: {renew_err}. Re-authenticating...")
                try:
                    new_token = _authenticate_approle(role_id, secret_id)
                    if new_token:
                        _client.token = new_token
                        logger.info("[Vault] Re-authenticated with AppRole successfully")
                    else:
                        logger.error("[Vault] Re-authentication failed — Vault calls may fail")
                except Exception as reauth_err:
                    logger.error(f"[Vault] Re-authentication error: {reauth_err}")

    _token_renewal_thread = threading.Thread(
        target=_renewal_loop,
        name="vault-token-renewal",
        daemon=True,   # dies when main process exits
    )
    _token_renewal_thread.start()
    logger.info("[Vault] Token renewal thread started (interval=45m)")


# ── Main connect function ─────────────────────────────────────────────────────

def connect_vault() -> bool:
    """
    Initialize connection to HashiCorp Vault.

    Phase 3 auth flow:
    1. Try AppRole: read role_id + secret_id from /vault/data/.approle_credentials
       → exchange for short-lived token → start renewal thread
    2. Fallback: use VAULT_TOKEN env var (for local dev without Docker)
    """
    global _client, _connected, _auth_method

    try:
        # ── Attempt AppRole auth ──────────────────────────────────────────────
        approle_creds = _load_approle_credentials()

        if approle_creds:
            role_id = approle_creds["role_id"]
            secret_id = approle_creds["secret_id"]
            token = _authenticate_approle(role_id, secret_id)

            if token:
                _client = hvac.Client(url=VAULT_ADDR, token=token)
                if _client.is_authenticated():
                    _auth_method = "approle"
                    logger.info(
                        f"[Vault] Connected via AppRole auth at {VAULT_ADDR}. "
                        f"Root token is NOT used by the application."
                    )
                    _start_token_renewal(role_id, secret_id)
                    _load_user_profiles()
                    _init_all_user_secrets()
                    _connected = True
                    return True
                else:
                    logger.error("[Vault] AppRole token obtained but authentication check failed")

        # ── Fallback: static VAULT_TOKEN ──────────────────────────────────────
        if VAULT_TOKEN:
            logger.warning(
                "[Vault] AppRole auth unavailable. Falling back to VAULT_TOKEN. "
                "This is acceptable for local dev but not for production."
            )
            _client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
            if _client.is_authenticated():
                _auth_method = "token"
                logger.info(f"[Vault] Connected via static token at {VAULT_ADDR}")
                _load_user_profiles()
                _init_all_user_secrets()
                _connected = True
                return True
            else:
                logger.error("[Vault] Static token authentication failed")
                _connected = False
                return False

        logger.error("[Vault] No auth method available (no AppRole creds, no VAULT_TOKEN)")
        _connected = False
        return False

    except Exception as e:
        logger.error(f"Vault connection failed: {e}")
        _connected = False
        return False


# ── User profile + credential management (unchanged from before) ──────────────

def _load_user_profiles():
    global _user_profiles
    path = Path(PROFILES_PATH)
    if not path.exists():
        logger.warning(f"User profiles not found at {PROFILES_PATH}, generating default 200 users")
        _user_profiles = [
            {"user_id": f"USR-{i:04d}", "role": "Employee", "home_region": "US-East"}
            for i in range(1, 201)
        ]
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            _user_profiles = json.load(f)
        logger.info(f"Loaded {len(_user_profiles)} user profiles for Vault credential seeding")
    except Exception as e:
        logger.error(f"Failed to load user profiles: {e}")
        _user_profiles = []


def _init_all_user_secrets():
    if not _user_profiles:
        logger.warning("No user profiles loaded — skipping Vault credential seeding")
        return

    created = 0
    skipped = 0

    for profile in _user_profiles:
        user_id = profile.get("user_id", "UNKNOWN")
        vault_path = f"hpe/users/{user_id}"

        try:
            existing = None
            try:
                existing = _client.secrets.kv.v2.read_secret_version(
                    path=vault_path,
                    raise_on_deleted_version=False,
                )
            except Exception:
                pass

            if existing and existing.get("data", {}).get("data", {}):
                skipped += 1
                continue

            creds = {
                "user_id": user_id,
                "role": profile.get("role", "Employee"),
                "home_region": profile.get("home_region", "Unknown"),
                "db_password": _generate_password(),
                "api_key": _generate_api_key(),
                "service_token": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "rotation_count": 0,
                "status": "active",
                "last_rotation_reason": "initial_provisioning",
            }

            _client.secrets.kv.v2.create_or_update_secret(
                path=vault_path,
                secret=creds,
            )
            created += 1

        except Exception as e:
            logger.warning(f"Vault: Failed to init credentials for {user_id}: {e}")

    logger.info(
        f"Vault: Initialized {created} new user credentials, {skipped} already existed "
        f"(total users: {len(_user_profiles)})"
    )


def is_connected() -> bool:
    return _connected


def rotate_credentials(reason: str = "threat_detected", user: str = "unknown",
                       threat_score: float = 0.0) -> Dict[str, Any]:
    global _rotation_count

    if not _client or not _connected:
        return {"success": False, "error": "Vault not connected"}

    try:
        _rotation_count += 1
        vault_path = f"hpe/users/{user}"

        current_rotation = 0
        try:
            existing = _client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                raise_on_deleted_version=False,
            )
            current_data = existing.get("data", {}).get("data", {})
            current_rotation = current_data.get("rotation_count", 0)
        except Exception:
            pass

        user_profile = next((p for p in _user_profiles if p.get("user_id") == user), {})

        new_creds = {
            "user_id": user,
            "role": user_profile.get("role", "Unknown"),
            "home_region": user_profile.get("home_region", "Unknown"),
            "db_password": _generate_password(),
            "api_key": _generate_api_key(),
            "service_token": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rotation_count": current_rotation + 1,
            "status": "rotated",
            "last_rotation_reason": reason,
            "triggered_by_threat_score": threat_score,
        }

        _client.secrets.kv.v2.create_or_update_secret(
            path=vault_path,
            secret=new_creds,
        )

        logger.info(
            f"Vault: Credentials rotated for {user} "
            f"(rotation #{current_rotation + 1}, reason={reason})"
        )

        return {
            "success": True,
            "user_id": user,
            "rotation_id": str(uuid.uuid4()),
            "rotation_number": current_rotation + 1,
            "global_rotation_count": _rotation_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "services_affected": ["database", "api_gateway", "service_mesh"],
            "new_credentials_hash": secrets.token_hex(8),
            "auth_method": _auth_method,
        }

    except Exception as e:
        logger.error(f"Vault credential rotation failed for {user}: {e}")
        return {"success": False, "error": str(e)}


def get_current_credentials() -> Dict[str, Any]:
    if not _client or not _connected:
        return {"error": "Vault not connected"}
    try:
        response = _client.secrets.kv.v2.read_secret_version(
            path="hpe/credentials",
            raise_on_deleted_version=False,
        )
        data = response.get("data", {}).get("data", {})
        return {
            "rotation_count": data.get("rotation_count", 0),
            "created_at": data.get("created_at", ""),
            "rotation_reason": data.get("rotation_reason", "initial"),
            "has_db_password": bool(data.get("db_password")),
            "has_api_key": bool(data.get("api_key")),
            "has_service_token": bool(data.get("service_token")),
        }
    except Exception as e:
        logger.error(f"Vault read error: {e}")
        return {"error": str(e)}


def get_rotation_count() -> int:
    return _rotation_count


def get_auth_method() -> str:
    """Returns which auth method is active: 'approle' or 'token'."""
    return _auth_method


def get_visible_credentials() -> Dict[str, Any]:
    if not _client or not _connected:
        return {"error": "Vault not connected", "rotation_count": _rotation_count}

    latest_user = _find_latest_rotated_user()
    if not latest_user:
        return {
            "rotation_count": _rotation_count,
            "db_password": "****",
            "api_key": "****",
            "service_token": "****",
            "created_at": "",
            "rotation_reason": "no_rotations_yet",
            "triggered_by_user": "",
            "threat_score": 0,
            "auth_method": _auth_method,
        }
    return {**latest_user, "auth_method": _auth_method}


def _find_latest_rotated_user() -> Optional[Dict[str, Any]]:
    if not _client or not _connected:
        return None

    latest = None
    latest_time = ""

    for profile in _user_profiles:
        user_id = profile.get("user_id", "")
        try:
            resp = _client.secrets.kv.v2.read_secret_version(
                path=f"hpe/users/{user_id}",
                raise_on_deleted_version=False,
            )
            data = resp.get("data", {}).get("data", {})
            if data.get("status") == "rotated":
                created = data.get("created_at", "")
                if created > latest_time:
                    latest_time = created
                    latest = data
        except Exception:
            continue

    if not latest:
        return None

    db_pw = latest.get("db_password", "")
    api_key = latest.get("api_key", "")
    svc_token = latest.get("service_token", "")

    return {
        "rotation_count": _rotation_count,
        "user_id": latest.get("user_id", ""),
        "role": latest.get("role", ""),
        "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
        "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
        "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
        "created_at": latest.get("created_at", ""),
        "rotation_reason": latest.get("last_rotation_reason", "initial"),
        "triggered_by_user": latest.get("user_id", ""),
        "threat_score": latest.get("triggered_by_threat_score", 0),
    }


def get_all_user_credentials() -> List[Dict[str, Any]]:
    if not _client or not _connected:
        return []

    results = []
    for profile in _user_profiles:
        user_id = profile.get("user_id", "")
        vault_path = f"hpe/users/{user_id}"
        try:
            resp = _client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                raise_on_deleted_version=False,
            )
            data = resp.get("data", {}).get("data", {})
            db_pw = data.get("db_password", "")
            api_key = data.get("api_key", "")
            svc_token = data.get("service_token", "")
            results.append({
                "user_id": user_id,
                "role": data.get("role", profile.get("role", "")),
                "home_region": data.get("home_region", profile.get("home_region", "")),
                "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
                "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
                "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
                "rotation_count": data.get("rotation_count", 0),
                "status": data.get("status", "unknown"),
                "created_at": data.get("created_at", ""),
                "last_rotation_reason": data.get("last_rotation_reason", ""),
            })
        except Exception as e:
            results.append({
                "user_id": user_id,
                "role": profile.get("role", ""),
                "home_region": profile.get("home_region", ""),
                "error": str(e),
                "status": "error",
            })
    return results


def get_user_credentials(user_id: str) -> Dict[str, Any]:
    if not _client or not _connected:
        return {"error": "Vault not connected"}

    vault_path = f"hpe/users/{user_id}"
    try:
        resp = _client.secrets.kv.v2.read_secret_version(
            path=vault_path,
            raise_on_deleted_version=False,
        )
        data = resp.get("data", {}).get("data", {})
        db_pw = data.get("db_password", "")
        api_key = data.get("api_key", "")
        svc_token = data.get("service_token", "")
        return {
            "user_id": user_id,
            "role": data.get("role", ""),
            "home_region": data.get("home_region", ""),
            "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
            "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
            "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
            "rotation_count": data.get("rotation_count", 0),
            "status": data.get("status", "unknown"),
            "created_at": data.get("created_at", ""),
            "last_rotation_reason": data.get("last_rotation_reason", ""),
            "triggered_by_threat_score": data.get("triggered_by_threat_score", 0),
        }
    except Exception as e:
        logger.error(f"Vault: Failed to read credentials for {user_id}: {e}")
        return {"error": str(e), "user_id": user_id}


def _generate_password(length: int = 32) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


def _generate_api_key() -> str:
    return f"hpe_{secrets.token_hex(24)}"


def disconnect_vault():
    global _connected, _renewal_stop_event
    _renewal_stop_event.set()   # stop renewal thread cleanly
    _connected = False
    logger.info("Vault disconnected")