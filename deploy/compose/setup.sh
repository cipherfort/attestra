#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Evaluate the platform with Docker Compose: generate every secret, start the stack, load the demo world.
#   AAP_IMAGE=ghcr.io/cipherfort/fortproof:vX.Y.Z deploy/compose/setup.sh   # a released image
#   deploy/compose/setup.sh             # without AAP_IMAGE: builds one from this checkout
#   deploy/compose/setup.sh --build     # always build from this checkout
# Then sign in at http://localhost:8000 as appsec / lead / admin / dev (password printed at the end).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
secrets="$here/secrets"
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }

if [ ! -d "$secrets" ]; then
  ( umask 077; mkdir -p "$secrets"
    pg="$(rand 24)"; s3key="aap$(rand 6 | tr -dc a-z0-9)"; s3secret="$(rand 30)"
    printf '%s' "$pg" > "$secrets/pg-password"
    printf '%s' "postgresql+psycopg://postgres:$pg@postgres:5432/aap" > "$secrets/database-url"
    for p in api worker hook reporting; do
      printf '%s' "postgresql+psycopg://aap_${p}_login:$(rand 24)@postgres:5432/aap" > "$secrets/database-url-$p"
    done
    client_secret="$(rand 32)"
    printf '%s' "$client_secret" > "$secrets/oidc-client-secret"
    printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$s3key" "$s3secret" > "$secrets/aws-credentials"
    printf 'RUSTFS_ACCESS_KEY=%s\nRUSTFS_SECRET_KEY=%s\n' "$s3key" "$s3secret" > "$secrets/rustfs.env"
    printf 'KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\nAAP_OIDC_CLIENT_SECRET=%s\nAAP_DEMO_PASSWORD=%s\n' \
      "$(rand 18)" "$client_secret" "$(rand 9)" > "$secrets/keycloak.env" )
  echo "generated $secrets (mode 700; never commit it)"
fi

if [ "${1:-}" = "--build" ] || [ -z "${AAP_IMAGE:-}" ]; then
  docker build -t aap:compose "$root"
  export AAP_IMAGE=aap:compose
fi
cd "$here"
docker compose up -d --wait api worker keycloak
docker compose exec -T worker aap demo seed >/dev/null
echo "Up: http://localhost:8000  (Keycloak: http://localhost:8180)"
echo "Sign in as appsec, lead, admin or dev; password: $(sed -n 's/^AAP_DEMO_PASSWORD=//p' "$secrets/keycloak.env")"
echo "Stop: docker compose -f deploy/compose/compose.yaml down   (add -v to delete the data)"
