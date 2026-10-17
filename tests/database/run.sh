#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apply schemas/database/*.sql to a throwaway PostgreSQL 16 container and run the security-property tests.
# Requires Docker. Usage: tests/database/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="aap-schema-test-$$"
IMAGE="${PG_IMAGE:-postgres:16-alpine}"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# tmpfs data dir: throwaway, fast, and independent of free space in the Docker VM
docker run -d --name "$NAME" --tmpfs /var/lib/postgresql/data:rw,size=512m \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=aap "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  # the entrypoint restarts the server after init; wait for the final instance
  docker exec "$NAME" psql -U postgres -d aap -c "select 1" >/dev/null 2>&1 && [ "$(docker logs "$NAME" 2>&1 | grep -c "ready to accept connections")" -ge 2 ] && break
  sleep 1
done

for f in "$ROOT"/schemas/database/*.sql; do
  echo "== applying $(basename "$f")"
  docker exec -i "$NAME" psql -v ON_ERROR_STOP=1 -q -U postgres -d aap < "$f"
done

echo "== running security-property tests"
docker exec -i "$NAME" psql -v ON_ERROR_STOP=1 -q -U postgres -d aap < "$ROOT/tests/database/test_schema_security.sql"
