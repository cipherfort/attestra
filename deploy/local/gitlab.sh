#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A local GitLab CE + runner for the GitLab adapter (ADR-033), set up from nothing with the platform's own
# `aap bootstrap gitlab`. Needs ~4 GB of Docker memory; first start takes several minutes.
#
#   deploy/local/gitlab.sh          # start, create the example-org group, the platform's read-only token, a runner
#
# Then run the live end-to-end test it prints. Secrets: deploy/local/.env (root password), deploy/local/.gitlab-admin-token
# (a 2-day setup token, mode 600, git-ignored), and the platform token in the dev secret store (~/.aap/secrets).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file="$here/.env"
url="http://127.0.0.1:8929"
touch "$env_file" && chmod 600 "$env_file"
grep -q '^GITLAB_ROOT_PASSWORD=' "$env_file" || \
  echo "GITLAB_ROOT_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" >> "$env_file"
compose=(docker compose -f "$here/gitlab.compose.yaml" --env-file "$env_file")
"${compose[@]}" up -d
echo "waiting for GitLab (first start: several minutes)..."
for _ in $(seq 120); do curl -sf -o /dev/null "$url/users/sign_in" && break; sleep 10; done
curl -sf -o /dev/null "$url/users/sign_in" || { echo "GitLab did not start" >&2; exit 1; }

admin_file="$here/.gitlab-admin-token"
if [ ! -s "$admin_file" ]; then
  ( umask 077
    "${compose[@]}" exec -T gitlab gitlab-rails runner '
      t = User.find_by_username("root").personal_access_tokens.create!(name: "aap-local-setup", scopes: ["api"],
                                                                        expires_at: 2.days.from_now)
      puts t.token' | tail -1 > "$admin_file" )
fi
GITLAB_ADMIN_TOKEN="$(cat "$admin_file")"; export GITLAB_ADMIN_TOKEN
api() { curl -sf -H "PRIVATE-TOKEN: $GITLAB_ADMIN_TOKEN" "$@"; }
api "$url/api/v4/groups/example-org" >/dev/null 2>&1 || \
  api -X POST "$url/api/v4/groups" -d name=example-org -d path=example-org -d visibility=internal >/dev/null

if ! "${compose[@]}" exec -T runner grep -q "url" /etc/gitlab-runner/config.toml 2>/dev/null; then
  runner_token="$(api -X POST "$url/api/v4/user/runners" -d runner_type=instance_type -d run_untagged=true \
    -d description=aap-local | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  # shellcheck disable=SC2016 # $RUNNER_TOKEN expands inside the container, keeping it off the host's command line
  "${compose[@]}" exec -T -e RUNNER_TOKEN="$runner_token" runner sh -c 'gitlab-runner register --non-interactive \
    --url http://gitlab:8929 --token "$RUNNER_TOKEN" --executor docker --docker-image alpine:3.20 \
    --docker-network-mode aap-gitlab_default --clone-url http://gitlab:8929' >/dev/null
  unset runner_token
fi

cd "$root/backend"
AAP_SECRETS_BACKEND="file" uv run aap bootstrap gitlab --url "$url" --group example-org --admin-token-env GITLAB_ADMIN_TOKEN
cat <<MSG

GitLab is up at $url (root password in deploy/local/.env). For the platform:
  export AAP_GITLAB_URL=$url AAP_GITLAB_GROUP=example-org
Live end-to-end test (components, real pipelines, forged-job rejection):
  cd backend && AAP_TEST_SERVICES=1 AAP_TEST_GITLAB_URL=$url AAP_TEST_GITLAB_HOST=gitlab.local.test:8929 \\
    AAP_TEST_GITLAB_ADMIN_TOKEN_FILE=$admin_file AAP_TEST_GITLAB_RO_TOKEN_FILE=\$HOME/.aap/secrets/gitlab-token \\
    uv run pytest -m service tests/integration/test_gitlab_live.py
MSG
