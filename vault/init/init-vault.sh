#!/bin/sh
# vault/init/init-vault.sh
# Phase 1: Initialize + unseal Vault, create KV v2 + hpe-dev-token
# Phase 2: Configure database secrets engine against PostgreSQL
# Phase 3: Create AppRole auth — backend gets role_id + secret_id instead of root token

VAULT_ADDR="http://vault:8200"
INIT_FILE="/vault/data/.initialized"
DB_ENGINE_FILE="/vault/data/.db_engine_configured"
APPROLE_FILE="/vault/data/.approle_configured"

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

  # Wait for Vault to be fully ready after unseal before mounting
  sleep 3

  echo ">>> Enabling KV v2..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"type":"kv","options":{"version":"2"}}' \
    "$VAULT_ADDR/v1/sys/mounts/secret" > /dev/null

  echo ">>> Creating hpe-dev-token (legacy fallback)..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"id":"hpe-dev-token","policies":["root"],"no_default_policy":true,"no_parent":true}' \
    "$VAULT_ADDR/v1/auth/token/create-orphan" > /dev/null

  echo ">>> KV v2 and hpe-dev-token ready."
fi

ROOT_TOKEN=$(cat /vault/data/.root_token)

# ── Phase 2: Database Secrets Engine ─────────────────────────────────────────
if [ -f "$DB_ENGINE_FILE" ]; then
  echo ">>> Database secrets engine already configured. Skipping."
else
  echo ">>> Enabling database secrets engine..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"type":"database"}' \
    "$VAULT_ADDR/v1/sys/mounts/database" > /dev/null

  echo ">>> Configuring PostgreSQL connection..."
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

# ── Phase 3: AppRole Auth ─────────────────────────────────────────────────────
if [ -f "$APPROLE_FILE" ]; then
  echo ">>> AppRole already configured. Reading existing role_id and secret_id..."
  ROLE_ID=$(cat /vault/data/.approle_role_id)
  SECRET_ID=$(cat /vault/data/.approle_secret_id)
else
  echo ">>> Creating hpe-backend policy..."
  # This policy grants exactly what the backend needs — no more, no less.
  # It can read/write user KV secrets, read database creds, and manage tokens.
  # It cannot list sys/mounts or access other Vault internals.
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{
      "policy": "path \"secret/data/hpe/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\npath \"secret/metadata/hpe/*\" {\n  capabilities = [\"list\", \"read\", \"delete\"]\n}\npath \"database/creds/hpe-backend-role\" {\n  capabilities = [\"read\"]\n}\npath \"database/creds/hpe-readonly-role\" {\n  capabilities = [\"read\"]\n}\npath \"sys/leases/renew\" {\n  capabilities = [\"update\"]\n}\npath \"sys/leases/revoke\" {\n  capabilities = [\"update\"]\n}\npath \"auth/token/renew-self\" {\n  capabilities = [\"update\"]\n}\npath \"auth/token/lookup-self\" {\n  capabilities = [\"read\"]\n}"
    }' \
    "$VAULT_ADDR/v1/sys/policies/acl/hpe-backend-policy" > /dev/null

  echo ">>> Enabling AppRole auth method..."
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{"type":"approle"}' \
    "$VAULT_ADDR/v1/sys/auth/approle" > /dev/null

  echo ">>> Creating hpe-backend AppRole..."
  # token_ttl=1h — backend token expires after 1 hour
  # token_max_ttl=24h — can be renewed up to 24 hours total
  # secret_id_ttl=0 — secret_id never expires (rotated manually in Phase 3+)
  # secret_id_num_uses=0 — secret_id can be used unlimited times
  wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{
      "policies": ["hpe-backend-policy"],
      "token_ttl": "1h",
      "token_max_ttl": "24h",
      "secret_id_ttl": "0",
      "secret_id_num_uses": 0
    }' \
    "$VAULT_ADDR/v1/auth/approle/role/hpe-backend" > /dev/null

  echo ">>> Fetching role_id..."
  ROLE_RESP=$(wget -qO- \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    "$VAULT_ADDR/v1/auth/approle/role/hpe-backend/role-id")
  ROLE_ID=$(echo "$ROLE_RESP" | grep -o '"role_id":"[^"]*"' | cut -d'"' -f4)

  echo ">>> Generating secret_id..."
  SECRET_RESP=$(wget -qO- \
    --header="Content-Type: application/json" \
    --header="X-Vault-Token: $ROOT_TOKEN" \
    --post-data='{}' \
    "$VAULT_ADDR/v1/auth/approle/role/hpe-backend/secret-id")
  SECRET_ID=$(echo "$SECRET_RESP" | grep -o '"secret_id":"[^"]*"' | cut -d'"' -f4)

  if [ -z "$ROLE_ID" ] || [ -z "$SECRET_ID" ]; then
    echo "ERROR: Failed to parse role_id or secret_id"
    echo "Role response: $ROLE_RESP"
    echo "Secret response: $SECRET_RESP"
    exit 1
  fi

  echo "$ROLE_ID" > /vault/data/.approle_role_id
  echo "$SECRET_ID" > /vault/data/.approle_secret_id
  touch "$APPROLE_FILE"

  echo ">>> AppRole configured."
fi

echo ""
echo ">>> role_id:    $ROLE_ID"
echo ">>> secret_id:  $SECRET_ID"

# Write role_id and secret_id to a file the backend container can read
# Both containers share the vault_data volume
cat > /vault/data/.approle_credentials << CREDS
VAULT_ROLE_ID=$ROLE_ID
VAULT_SECRET_ID=$SECRET_ID
CREDS

echo ""
echo "=========================================="
echo "  Vault fully ready! (Phase 1+2+3)"
echo "  - KV v2 at secret/"
echo "  - Database engine at database/"
echo "  - hpe-backend-role: read/write, TTL=1h"
echo "  - hpe-readonly-role: read only, TTL=30m"
echo "  - AppRole: hpe-backend"
echo "  - Policy: hpe-backend-policy"
echo "  - Credentials: /vault/data/.approle_credentials"
echo "=========================================="