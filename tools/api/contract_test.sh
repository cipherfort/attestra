#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Contract test (Schemathesis): every implemented GET operation against a running API with demo data.
# Fails on server errors, responses that violate the OpenAPI schema, and undocumented status codes.
#   tools/api/contract_test.sh http://127.0.0.1:8765/api/v1        (API started with AAP_AUTH_MODE=dev)
set -euo pipefail
url="${1:?base URL, e.g. http://127.0.0.1:8765/api/v1}"
here="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d -t aap-contract.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
run() {  # persona, then filters for tools/api/implemented_spec.py
  python3 "$here/tools/api/implemented_spec.py" --methods get "${@:2}" > "$tmp/spec.yaml"
  uvx --from "schemathesis==4.*" schemathesis run "$tmp/spec.yaml" --url "$url" \
    --checks not_a_server_error,response_schema_conformance,status_code_conformance \
    --max-examples "${AAP_CONTRACT_EXAMPLES:-25}" --no-color -H "X-AAP-Dev-User: $1"
}
run cpatel --exclude-paths '^/admin'      # AppSec engineer: organization-wide reads
run padmin --paths '^/admin'              # platform admin: the admin screens
