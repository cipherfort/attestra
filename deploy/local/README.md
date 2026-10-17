# Local integration stack

Every external system the platform talks to, on one machine, started from nothing. Use it to:
- develop the connectors;
- run the opt-in service tests;
- see the platform with production sign-in (OIDC) instead of the demo persona switcher.

```bash
deploy/local/bootstrap.sh            # core: PostgreSQL 16, OIDC provider (Entra stand-in), Azurite (Blob stand-in)
deploy/local/bootstrap.sh scanners   # + Dependency-Track 4.14.5 + DefectDojo 3.4.0 (~5 GB RAM, first start ~5 min)
source deploy/local/aap.env && cd backend
uv run aap demo seed                             # optional: four demo applications (evidence goes to Azurite)
# each process on its own least-privilege login (aap.env's URL is the admin login, for these CLI commands only)
env -u AAP_DATABASE_URL AAP_DATABASE_URL_FILE=$HOME/.aap/secrets/database-url-api uv run aap api --port 8765
env -u AAP_DATABASE_URL AAP_DATABASE_URL_FILE=$HOME/.aap/secrets/database-url-worker uv run aap worker   # second terminal
uv run aap integrations run dependency_track     # upload SBOMs to the real Dependency-Track and pull findings
uv run aap integrations status
```

Sign in at http://localhost:8765 (no password: the local identity provider signs you in). To try onboarding, choose
**Register an application**, pick "Paste the files", and paste `templates/repo-contract/.security/application.yaml` with
any repository name and a made-up numeric id. A Tier 1/2 result waits for approval, and the local sign-in is the only
user, so the platform refuses to let you approve your own request (segregation of duties). Approving needs a second
person; the integration tests (`backend/tests/integration/test_onboarding.py`) cover that path.

The script:
1. Generates passwords into `deploy/local/.env` (mode 600, git-ignored).
2. Starts the containers on `127.0.0.1` only.
3. Migrates the database and loads configuration.
4. Runs the real bootstrap commands. Dependency-Track: forced admin password change, `aap-platform` team with four permissions, API key, OSV enabled. DefectDojo: service user scoped to one organization.
5. Writes the settings to `deploy/local/aap.env` (mode 600). Credentials go to the dev secret store (`~/.aap/secrets`, 0600).

| Service | Port | Stand-in for | Difference from production |
|---|---|---|---|
| PostgreSQL 16 | 55433 | Azure PostgreSQL Flexible Server | Password login, no TLS |
| mock-oauth2-server 2.1.10 | 8090 | Entra ID | Signs everyone in as "Local Developer" (appsec_engineer); client secret instead of the managed-identity federated credential |
| Azurite 3.35.0 | 10000 | Azure Blob Storage | **Does not enforce immutability policies.** The platform's write-once checks are exercised; the WORM policy is verified only in Azure |
| Dependency-Track 4.14.5 | 8081 | Same | Embedded state on a Docker volume |
| DefectDojo 3.4.0 | 8082 | Same | Same images as `examples/terraform/azure/modules/scanners` |

Not here, because they are SaaS accounts the project creates rather than software you can run: GitHub (`aap bootstrap github-app` against a real organization), Jira (`aap bootstrap jira` against a real site), Defender for Cloud, Security Hub and Sentinel. Their connectors are tested against recorded API shapes and moto (`backend/tests`).

Stop: `docker compose -f deploy/local/compose.yaml --profile scanners down` (add `-v` to delete the data).

## Opt-in service tests

```bash
set -a; . deploy/local/.env; set +a
cd backend && AAP_TEST_SERVICES=1 AAP_TEST_DD_URL=http://127.0.0.1:8082 AAP_TEST_DD_ADMIN_PASSWORD="$DD_ADMIN_PASSWORD" \
  AAP_TEST_DD_SERVICE_PASSWORD="$(cat ~/.aap/secrets/defectdojo-service-password)" uv run pytest -m service
```

These start their own Dependency-Track, OIDC and Azurite containers, and use the running DefectDojo.
