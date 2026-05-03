"""
config.py — Environment configuration for the HPE pipeline backend.
"""

import os

# ── Infrastructure connections ──────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "hpe-dev-token")

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
    "ALLOW":   0.3,   # Below this → allow
    "MONITOR": 0.6,   # Between ALLOW and MONITOR → monitor
    "BLOCK":   0.85,  # Between MONITOR and BLOCK → block
    # Above BLOCK → CRITICAL_ALERT
}

# ── Server info ────────────────────────────────────────────────────────────────
SERVER_LOCATION = {"lat": 12.97, "lng": 77.59, "city": "Bangalore, India"}
APP_NAME = "HPE"
APP_TAGLINE = "HPE by project interns"
APP_VERSION = "1.0.0"