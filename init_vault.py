# init_vault.py
import subprocess
import json
import os

print("Initializing Vault...")
result = subprocess.run(
    ["docker", "exec", "hpe-vault", "vault", "operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json"],
    capture_output=True, text=True
)

if result.returncode != 0:
    print("Vault might already be initialized. If it is sealed, you need to unseal it manually.")
    print("Error:", result.stderr)
    exit(1)

keys = json.loads(result.stdout)
unseal_key = keys["unseal_keys_b64"][0]
root_token = keys["root_token"]

# Save keys locally just in case
with open("vault_keys.json", "w") as f:
    json.dump(keys, f, indent=4)

print("Unsealing Vault...")
subprocess.run(["docker", "exec", "hpe-vault", "vault", "operator", "unseal", unseal_key])

print("\n✅ Vault is Initialized, Unsealed, and Persistent!")
print("="*50)
print(f"YOUR NEW ROOT TOKEN: {root_token}")
print("="*50)
print("\nNext Steps:")
print("1. Copy the Root Token above.")
print("2. Open docker-compose.yml")
print("3. Under the 'backend' service, change 'VAULT_TOKEN=hpe-dev-token' to 'VAULT_TOKEN=<your_new_token>'")
print("4. Run: docker-compose up -d")