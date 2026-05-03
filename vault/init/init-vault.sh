#!/bin/sh
# vault/init/init-vault.sh

VAULT_ADDR="http://vault:8200"
INIT_FILE="/vault/data/.initialized"

echo ">>> Waiting for Vault API to be reachable..."
i=0
while [ $i -lt 40 ]; do
  HTTP_CODE=$(wget -qO- --server-response "$VAULT_ADDR/v1/sys/health" 2>&1 | grep "HTTP/" | awk '{print $2}' | tail -1)
  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "429" ] || [ "$HTTP_CODE" = "472" ] || [ "$HTTP_CODE" = "473" ] || [ "$HTTP_CODE" = "501" ] || [ "$HTTP_CODE" = "503" ]; then
    echo ">>> Vault HTTP reachable (code: $HTTP_CODE)"
    break
  fi
  echo "    Waiting... attempt $i/40 (HTTP: $HTTP_CODE)"
  i=$((i+1))
  sleep 3
done

# Check initialized state via API
HEALTH=$(wget -qO- "$VAULT_ADDR/v1/sys/health" 2>/dev/null || echo '{}')
echo ">>> Health response: $HEALTH"

INITIALIZED=$(echo "$HEALTH" | grep -o '"initialized":[a-z]*' | grep -o '[a-z]*$')
echo ">>> Initialized: $INITIALIZED"

if [ "$INITIALIZED" = "true" ] && [ -f "$INIT_FILE" ]; then
  echo ">>> Already initialized. Unsealing via API..."
  UNSEAL_KEY=$(cat /vault/data/.unseal_key)
  wget -qO- \
    --header="Content-Type: application/json" \
    --post-data="{\"key\":\"$UNSEAL_KEY\"}" \
    "$VAULT_ADDR/v1/sys/unseal"
  echo ">>> Unsealed. Done."
  exit 0
fi

echo ">>> Initializing Vault via API..."
INIT_RESPONSE=$(wget -qO- \
  --header="Content-Type: application/json" \
  --post-data='{"secret_shares":1,"secret_threshold":1}' \
  "$VAULT_ADDR/v1/sys/init")

echo ">>> Init response: $INIT_RESPONSE"

# Parse using cut — works reliably without grep/sed on any shell
UNSEAL_KEY=$(echo "$INIT_RESPONSE" | grep -o '"keys_base64":\["[^"]*"' | cut -d'"' -f4)
ROOT_TOKEN=$(echo "$INIT_RESPONSE" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)

echo ">>> Unseal key parsed: $UNSEAL_KEY"
echo ">>> Root token parsed: $ROOT_TOKEN"

if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
  echo "ERROR: Failed to parse unseal key or root token from init response."
  echo "Full response was: $INIT_RESPONSE"
  exit 1
fi

echo "$UNSEAL_KEY" > /vault/data/.unseal_key
echo "$ROOT_TOKEN" > /vault/data/.root_token
touch "$INIT_FILE"

echo ">>> Unsealing via API..."
UNSEAL_RESP=$(wget -qO- \
  --header="Content-Type: application/json" \
  --post-data="{\"key\":\"$UNSEAL_KEY\"}" \
  "$VAULT_ADDR/v1/sys/unseal")
echo ">>> Unseal response: $UNSEAL_RESP"

echo ">>> Enabling KV v2 via API..."
wget -qO- \
  --header="Content-Type: application/json" \
  --header="X-Vault-Token: $ROOT_TOKEN" \
  --post-data='{"type":"kv","options":{"version":"2"}}' \
  "$VAULT_ADDR/v1/sys/mounts/secret" || true

echo ">>> Creating hpe-dev-token via API..."
TOKEN_RESP=$(wget -qO- \
  --header="Content-Type: application/json" \
  --header="X-Vault-Token: $ROOT_TOKEN" \
  --post-data='{"id":"hpe-dev-token","policies":["root"],"no_default_policy":true,"no_parent":true}' \
  "$VAULT_ADDR/v1/auth/token/create-orphan")
echo ">>> Token response: $TOKEN_RESP"

echo ""
echo "=========================================="
echo "  Vault is ready!"
echo "  hpe-dev-token created for backend"
echo "=========================================="