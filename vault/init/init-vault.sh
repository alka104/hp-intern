#!/bin/sh
# vault/init/init-vault.sh
# Phase 1: Initialize + unseal Vault, create KV v2 + hpe-dev-token
# Phase 2: Configure database secrets engine against PostgreSQL

VAULT_ADDR="http://vault:8200"
INIT_FILE="/vault/data/.initialized"
DB_ENGINE_FILE="/vault/data/.db_engine_configured"

# ── Wait for Vault HTTP API ───────────────────────────────────────────────────
echo ">>> Waiting for Vault API to be reachable..."
i=0
while [ $i -lt 40 ]; do
  HTTP_CODE=$(wget -qO- --server-response "$VAULT_ADDR/v1/sys/health" 2>&1 \
    | grep "HTTP/" | awk '{print $2}' | tail -1)
  case "$HTTP_CODE" in
    200|429|472|473|501|503) break ;;
  esac
  echo "    Waiting... attempt $i/40"
  i=$((i+1))
  sleep 3
done
echo ">>> Vault API reachable."

# ── Initialize or unseal ──────────────────────────────────────────────────────
HEALTH=$(wget -qO- "$VAULT_ADDR/v1/sys/health" 2>/dev/null || echo '{}')
INITIALIZED=$(echo "$HEALTH" | grep -o '"initialized":[a-z]*' | grep -o '[a-z]*$')
echo ">>> Initialized: $INITIALIZED"

if [ "$INITIALIZED" = "true" ] && [ -f "$INIT_FILE" ]; then
  echo ">>> Already initialized. Unsealing..."
  UNSEAL_KEY=$(cat /vault/data/.unseal_key)
  ROOT_TOKEN=$(cat /vault/data/.root_token)
  wget -qO- \
    --header="Content-Type: application/json" \
    --post-data="{\"key\":\"$UNSEAL_KEY\"}" \
    "$VAULT_ADDR/v1/sys/unseal" > /dev/null
  echo ">>> Unsealed."
else
  echo ">>> First-time initialization..."
  INIT_RESPONSE=$(wget -qO- \
    --header="Content-Type: application/json" \
    --post-data='{"secret_shares":1,"secret_threshold":1}' \
    "$VAULT_ADDR/v1/sys/init")

  UNSEAL_KEY=$(echo "$INIT_RESPONSE" | grep -o '"keys_base64":\["[^"]*"' | cut -d'"' -f4)
  ROOT_TOKEN=$(echo "$INIT_RESPONSE" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)

  if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
    echo "ERROR: Failed to parse init response: $INIT_RESPONSE"
    exit 1
  fi

  echo "$UNSEAL_KEY" > /vault/data/.unseal_key
  echo "$ROOT_TOKEN" > /vault/data/.root_token
  touch "$INIT_FILE"

  echo ">>> Unsealing..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --post-data="{\"key\":\"$UNSEAL_KEY\"}" \
    "$VAULT_ADDR/v1/sys/unseal" > /dev/null

  echo ">>> Enabling KV v2..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"type":"kv","options":{"version":"2"}}' \
    "$VAULT_ADDR/v1/sys/mounts/secret" > /dev/null

  echo ">>> Creating hpe-dev-token..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"id":"hpe-dev-token","policies":["root"],"no_default_policy":true,"no_parent":true}' \
    "$VAULT_ADDR/v1/auth/token/create-orphan" > /dev/null

  echo ">>> KV v2 and hpe-dev-token ready."
fi

# ── Phase 2: Database Secrets Engine ─────────────────────────────────────────
ROOT_TOKEN=$(cat /vault/data/.root_token)

if [ -f "$DB_ENGINE_FILE" ]; then
  echo ">>> Database secrets engine already configured. Skipping."
else
  echo ">>> Enabling database secrets engine..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"type":"database"}' \
    "$VAULT_ADDR/v1/sys/mounts/database" > /dev/null

  echo ">>> Configuring PostgreSQL connection in Vault..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{
      "plugin_name": "postgresql-database-plugin",
      "allowed_roles": ["hpe-backend-role","hpe-readonly-role"],
      "connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/hpedb?sslmode=disable",
      "username": "vault-root",
      "password": "vault-root-secret"
    }' \
    "$VAULT_ADDR/v1/database/config/hpe-postgres" > /dev/null

  echo ">>> Creating hpe-backend-role (read/write, TTL=1h)..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{
      "db_name": "hpe-postgres",
      "creation_statements": [
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\''",
        "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"",
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\""
      ],
      "revocation_statements": [
        "REASSIGN OWNED BY \"{{name}}\" TO \"vault-root\"",
        "DROP OWNED BY \"{{name}}\"",
        "DROP ROLE IF EXISTS \"{{name}}\""
      ],
      "default_ttl": "1h",
      "max_ttl": "24h"
    }' \
    "$VAULT_ADDR/v1/database/roles/hpe-backend-role" > /dev/null

  echo ">>> Creating hpe-readonly-role (read only, TTL=30m)..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{
      "db_name": "hpe-postgres",
      "creation_statements": [
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\''",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\""
      ],
      "revocation_statements": [
        "REASSIGN OWNED BY \"{{name}}\" TO \"vault-root\"",
        "DROP OWNED BY \"{{name}}\"",
        "DROP ROLE IF EXISTS \"{{name}}\""
      ],
      "default_ttl": "30m",
      "max_ttl": "2h"
    }' \
    "$VAULT_ADDR/v1/database/roles/hpe-readonly-role" > /dev/null

  touch "$DB_ENGINE_FILE"
  echo ">>> Database secrets engine configured."
fi

echo ""
echo "=========================================="
echo "  Vault fully ready!"
echo "  - KV v2 at secret/"
echo "  - Database engine at database/"
echo "  - hpe-backend-role: read/write, TTL=1h"
echo "  - hpe-readonly-role: read only, TTL=30m"
echo "  - hpe-dev-token active for backend"
echo "=========================================="