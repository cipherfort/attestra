# aap: Attestra backend

Python 3.12 · FastAPI · SQLAlchemy 2 · PostgreSQL 16 · one package, three processes (`api`, `hook`, `worker`). Design: [`docs/architecture/02-platform-architecture.md`](../docs/architecture/02-platform-architecture.md).

## Run the demo (about 2 minutes)

```bash
# 1. A throwaway PostgreSQL 16 (tmpfs: nothing persists)
docker run -d --name aap-demo-db --tmpfs /var/lib/postgresql/data:rw,size=512m \
  -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=aap -p 127.0.0.1:55432:5432 postgres:16-alpine

# 2. Migrate, then seed four demo applications through the real ingestion/evaluation code
cd backend
export AAP_DATABASE_URL=postgresql+psycopg://postgres:demo@127.0.0.1:55432/aap
uv sync && uv run aap migrate && uv run aap demo seed
uv run aap demo report            # terminal scorecards, CVE impact, rejected evidence

# 3. UI + API on one origin (build the UI once: cd ../frontend && npm ci && npm run build)
AAP_AUTH_MODE=dev AAP_ENV=development uv run aap api --port 8765
open http://localhost:8765        # switch persona top-right to see role- and team-scoped views
```

Stop: `docker rm -f aap-demo-db`.

## What the demo shows

| App | Tier | What to look at |
|---|---|---|
| Claims API | 1 | Log4Shell (CISA KEV) on an internet-facing Tier 1 app → **P1, 7-day SLA**, with "why". Verified SAST/SBOM/DAST evidence; IaC repo unscanned; dependency-review not a required check. |
| Payments Portal | 2 | SAST **partial** (Go not analysed); exposed, still-valid secret → P1 and triage overdue; owners unresolved; a **forged evidence** submission rejected (`UNTRUSTED_PRODUCER`). |
| HR Leave Tracker | 3 | Code scanning "enabled" but never ran → **no evidence** ("configuration alone does not prove the control operates"); 120-day-old SBOM → **stale** → "possibly affected" by CVEs. |
| Team Wiki Helper | 4 | Prototype with no SBOM → "possibly affected", never "not affected". |

Personas: `ajones` (Claims champion: sees only Claims), `ekim` (Payments engineer), `dlee` (Benefits security lead: both Benefits apps), `cpatel` (AppSec, organisation-wide; can confirm false positives), `fwong` (executive: aggregates only, no finding detail).

## Status

| Area | Status |
|---|---|
| Domain: classification, risk model (safe expression evaluator), freshness engine, evidence verification, hash chain, fingerprints, licence policy, SBOM quality, maturity | **IMPLEMENTED**, unit + property tests |
| Evaluators | **IMPLEMENTED** for 39 of 48 catalogue controls; the other 9 report `error: not implemented` (never a guessed state) |
| Ingestion: pull-based, verified (approved workflow SHA, binding, digests, attestation hook, limits, zip-bomb safe), write-once blob store, SARIF → findings, re-scan closure, regression reopen, SBOM inventory | **IMPLEMENTED** |
| Database: migrations (`0001_core` = verified DDL), RLS, ledger guards, partitions, roles (`aap_api`/`aap_worker`/`aap_hook`) | **IMPLEMENTED** |
| API (23 endpoints, every one with `x-permission`), policy module, team/role scoping, 404-not-403, ETags, false-positive two-person rule with audited denials, CSP, problem+json | **IMPLEMENTED** |
| Webhook receiver (HMAC, replay protection, identifiers-only jobs, least-privilege role) and worker (SKIP LOCKED queue, backoff, dead-letter, scheduler sweep with chain verification) | **IMPLEMENTED** |
| Web UI (portfolio, application scorecard, evidence chain, finding "why" + actions, CVE impact, leadership) | **IMPLEMENTED** (`../frontend`) |
| Sign-in: OIDC authorization code + PKCE through the BFF, server-side sessions (hash-only ids, 30 min idle / 8 h absolute), CSRF on writes, roles from Entra app roles + platform-scoped assignments by group, bearer tokens for service clients, managed-identity federated credential (no client secret) | **IMPLEMENTED**. Tested against an in-process IdP (attack cases) and a real OIDC server (`-m service`). Entra apps/roles/groups: `examples/terraform/azure/modules/entra`. |
| GitHub: App JWT + installation tokens (read-only scopes; Key Vault signing with a non-exportable key), settings connector → `repo.*` / `registry.application` / `repo.threat_model` / `scan.secrets` evidence, secret alerts → findings | **IMPLEMENTED**, tested against recorded API shapes. App created by `aap bootstrap github-app`. |
| Sigstore attestation verification (C3) | **IMPLEMENTED**: in-process (public-good) and `gh attestation verify` offline (GitHub instance, private repos on Enterprise Cloud). Tested against a real GitHub attestation. |
| Dependency-Track, DefectDojo | **IMPLEMENTED** connectors + bootstrap, **tested against the real services** (4.14.5, 3.4.0). |
| Jira | **IMPLEMENTED** (grouped dedup, crash-safe idempotency, closure only by evidence, regression reopen). Contract fake + opt-in live test. |
| Defender for Cloud, AWS Security Hub | **IMPLEMENTED** (Resource Graph paging; STS web identity, no keys). Recorded responses / moto. |
| Sentinel | **IMPLEMENTED**: curated events derived from the ledgers, deduplicated per window, daily chain checkpoint, at-least-once dispatch. Recorded responses. |
| Evidence store | **IMPLEMENTED**: `AzureBlobStore` (conditional writes, re-hash on read; tested on Azurite) and `LocalBlobStore`. |
| Integration registry | **IMPLEMENTED**: `aap integrations status|run`, `GET /api/v1/integrations`, `connector_runs`, scheduled syncs only for configured integrations. |
| Exceptions API, assessments API, monthly P4 hygiene ticket, role-assignment admin UI | DESIGNED (backlog) |

## Tests

```bash
uv run pytest            # 207 tests: unit + integration (starts a throwaway postgres:16 container)
AAP_TEST_SERVICES=1 uv run pytest -m service   # real Dependency-Track, DefectDojo, OIDC server, Azurite (deploy/local)
uv run mypy              # strict, whole package
uv run ruff check src tests migrations
```

Running the tests and the demo found and fixed real defects, including: an executive inheriting finding-level read access (a default `engineer` role); denial audit records rolled back with the refused request; the webhook role missing privileges `ON CONFLICT` needs; threat models evaluated per repository instead of per application. Each now has a regression test.
