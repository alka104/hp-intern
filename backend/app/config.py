"""
config.py — Environment configuration for the HPE pipeline backend.
"""

import os

# ── Infrastructure connections ──────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")

# ── Phase 3: AppRole auth — VAULT_TOKEN is gone ────────────────────────────────
# The backend no longer uses a long-lived root token.
# It reads role_id + secret_id from the shared vault_data volume at startup
# and exchanges them for a short-lived token (TTL=1h, auto-renewed).
# VAULT_TOKEN kept as fallback for local dev without Docker.
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")

# Path to the approle credentials file written by vault-init
# Mounted as vault_data:/vault/data:ro in docker-compose.yml
VAULT_APPROLE_CREDS_FILE = os.getenv(
    "VAULT_APPROLE_CREDS_FILE",
    "/vault/data/.approle_credentials"
)

# ── PostgreSQL (Phase 2 — Vault database secrets engine) ──────────────────────
POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://localhost:5432/hpedb")

# ── Model paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "model_output", "pipeline_artifacts_v2.joblib"))
TEST_EVENTS_PATH = os.getenv("TEST_EVENTS_PATH", os.path.join(BASE_DIR, "model_output", "test_events.json"))
PROFILES_PATH = os.getenv("PROFILES_PATH", os.path.join(BASE_DIR, "model_output", "user_profiles.json"))
SAMPLE_EVENTS_PATH = os.getenv("SAMPLE_EVENTS_PATH", os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "model_output", "sample_events.json"
))

# ── Kafka topics ───────────────────────────────────────────────────────────────
KAFKA_RAW_EVENTS_TOPIC = "hpe-raw-events"
KAFKA_ALERTS_TOPIC = "hpe-alerts"
KAFKA_AUDIT_TOPIC = "hpe-audit"

# ── Elasticsearch indices ──────────────────────────────────────────────────────
ES_AUDIT_INDEX = "hpe-audit-logs"
ES_THREATS_INDEX = "hpe-threats"

# ── Vault paths ────────────────────────────────────────────────────────────────
VAULT_SECRETS_PATH = "secret/data/hpe/credentials"
VAULT_DB_BACKEND_ROLE = "hpe-backend-role"    # read/write, TTL=1h
VAULT_DB_READONLY_ROLE = "hpe-readonly-role"  # read only,  TTL=30m

# ── Threat thresholds ──────────────────────────────────────────────────────────
THREAT_LEVELS = {
    "ALLOW":   0.3,
    "MONITOR": 0.6,
    "BLOCK":   0.85,
}

# ── Server info ────────────────────────────────────────────────────────────────
SERVER_LOCATION = {"lat": 12.97, "lng": 77.59, "city": "Bangalore, India"}
APP_NAME = "HPE"
APP_TAGLINE = "HPE by project interns"
APP_VERSION = "1.0.0"