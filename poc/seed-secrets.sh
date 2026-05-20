#!/usr/bin/env bash
# Seed demo KV secrets into the PoC Vault. Run after the stack is up
# and bootstrap-vault has enabled the audit device.
#
# Usage (run from the repo root):
#   ./poc/seed-secrets.sh
#   COMPOSE_FILE=poc/docker-compose.yml ./poc/seed-secrets.sh
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-./docker-compose.yml}"

vault_exec() {
  docker compose -f "$COMPOSE_FILE" exec -T \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_TOKEN=root \
    vault vault "$@"
}

vault_exec kv put secret/cluster_a/accounts-db user=accounts pass=v1
vault_exec kv put secret/cluster_a/ledger-db   user=ledger   pass=v1
vault_exec kv put secret/cluster_b/accounts-db user=accounts pass=v1
vault_exec kv put secret/cluster_b/ledger-db   user=ledger   pass=v1
vault_exec kv put secret/shared/jwt-key        value=jwt-v1
echo "seeded."