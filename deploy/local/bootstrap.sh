#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bring up every external system the platform uses, locally and from nothing, then create the platform's
# credentials in them with the same `aap bootstrap` commands production uses (docs/operations/integration-bootstrap.md).
#
#   deploy/local/bootstrap.sh            # core: postgres + OIDC (Entra stand-in) + Azurite
#   deploy/local/bootstrap.sh scanners   # + Dependency-Track + DefectDojo (~5 GB RAM, ~5 min first time)
#
# Writes deploy/local/.env (generated passwords, mode 600, git-ignored) and the dev secret store (~/.aap/secrets).
# Prints the environment to export for `aap api` / `aap worker`. Nothing leaves this machine except the scanners'
# advisory downloads (OSV/NVD) and image pulls.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file="$here/.env"
compose=(docker compose -f "$here/compose.yaml" --env-file "$env_file")
profile="${1:-core}"

rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }

if [ ! -f "$env_file" ]; then
  umask 077
  cat > "$env_file" <<EOF
AAP_PG_PASSWORD=$(rand 24)
DD_DB_PASSWORD=$(rand 24)
DD_SECRET_KEY=$(rand 48)
DD_AES_KEY=$(rand 24)
DD_ADMIN_PASSWORD=$(rand 24)
EOF
  echo "generated $env_file (mode 600)"
fi
set -a
# shellcheck source=/dev/null  # generated above
. "$env_file"
set +a

if [ "$profile" = "scanners" ]; then
  "${compose[@]}" --profile scanners up -d
else
  "${compose[@]}" up -d postgres oidc azurite
fi

wait_for() { # url, what, seconds
  for _ in $(seq 1 "$3"); do curl -sf -o /dev/null "$1" && return 0; sleep 2; done
  echo "timed out waiting for $2 ($1)" >&2; return 1
}
wait_for "http://127.0.0.1:8090/aap/.well-known/openid-configuration" "OIDC provider" 60
until "${compose[@]}" exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done

export AAP_DATABASE_URL="postgresql+psycopg://postgres:${AAP_PG_PASSWORD}@127.0.0.1:55433/aap"
export AAP_SECRETS_BACKEND=file
cd "$root/backend"
uv run aap migrate
uv run aap config load --git-sha local
uv run aap bootstrap oidc-dev >/dev/null
uv run aap db provision-logins all >/dev/null   # per-process logins; URLs in the dev secret store (database-url-api, ...)
# the evidence container (Terraform creates it in Azure); Azurite's well-known dev key is public, not a secret
uv run python - <<'PY'
from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient
key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
svc = BlobServiceClient.from_connection_string(
    f"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey={key};"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;")
try:
    svc.create_container("evidence")
except ResourceExistsError:
    pass
PY

declare -a settings=(
  "AAP_DATABASE_URL=$AAP_DATABASE_URL"
  "AAP_AUTH_MODE=oidc" "AAP_ENV=development"
  "AAP_OIDC_ISSUER=http://localhost:8090/aap" "AAP_OIDC_CLIENT_ID=aap-web"
  "AAP_OIDC_TENANT_ID=00000000-0000-4000-8000-00000000000a" "AAP_PUBLIC_URL=http://localhost:8765"
  "AAP_BLOB_CONNECTION_STRING=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
)

if [ "$profile" = "scanners" ]; then
  wait_for "http://127.0.0.1:8081/api/version" "Dependency-Track" 150
  uv run aap bootstrap dependency-track --url http://127.0.0.1:8081
  wait_for "http://127.0.0.1:8082/login" "DefectDojo" 200
  DD_ADMIN_PASSWORD="$DD_ADMIN_PASSWORD" uv run aap bootstrap defectdojo --url http://127.0.0.1:8082 --admin-password-env DD_ADMIN_PASSWORD
  settings+=("AAP_DT_URL=http://127.0.0.1:8081" "AAP_DD_URL=http://127.0.0.1:8082")
fi

out="$here/aap.env"
( umask 077; : > "$out"; for s in "${settings[@]}"; do printf "export %q\n" "$s" >> "$out"; done )
echo
echo "Local integrations are up. Settings written to deploy/local/aap.env (mode 600; contains the local DB password):"
echo "  source deploy/local/aap.env && cd backend"
echo "  env -u AAP_DATABASE_URL AAP_DATABASE_URL_FILE=\$HOME/.aap/secrets/database-url-api uv run aap api --port 8765"
echo "  env -u AAP_DATABASE_URL AAP_DATABASE_URL_FILE=\$HOME/.aap/secrets/database-url-worker uv run aap worker"
echo "  uv run aap integrations status"
echo
echo "Sign in at http://localhost:8765 (the local OIDC provider signs you in as 'Local Developer', appsec_engineer)."
echo "Still yours to create (accounts the project owns, never assumed): a GitHub organization (aap bootstrap github-app),"
echo "a Jira site (aap bootstrap jira). Azure/AWS/Sentinel: examples/terraform/azure."
