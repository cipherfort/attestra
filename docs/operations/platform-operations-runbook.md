# Platform Operations Runbook

| | |
|---|---|
| Status | DESIGNED. Commands reference components that do not exist yet; verify each step when the platform is built (E20-F03-S02). |
| Owner | AppSec platform team (on-call) |
| Related | [DR plan](disaster-recovery-plan.md), [Backup and restore](backup-and-restore-plan.md), [Incident response](../runbooks/incident-response.md), [ADR-027](../../adr/ADR-027-observability.md) |

## 1. Service overview

| Component | Runs as | Health signal |
|---|---|---|
| `aap-web` (API + BFF + UI) | Container App, internal ingress, 2–6 replicas | `/health/ready`, availability SLO 99.5% |
| `aap-hook` (webhook receiver) | Container App, external ingress (GitHub IPs), 2–4 replicas | p99 latency < 200 ms, 401 rate |
| `aap-worker` (queues: ingest, github-sync, evaluate, risk, tickets, siem, scheduler) | Container App, KEDA-scaled per queue | Queue age p95 < 5 min, dead-letter count |
| PostgreSQL Flexible Server | Zone-redundant HA | CPU, connections, replication lag, storage |
| Blob (evidence-*) | WORM containers | Capacity, failed writes |
| Key Vault | — | Secret expiry alerts |

## 2. Routine operations

| Task | Frequency | Procedure |
|---|---|---|
| Check SLO dashboard and connector health | Daily (business hours) | Azure Monitor workbook "AAP SLOs". Any connector stale > 2× interval → §4.3. |
| Review dead-lettered jobs | Daily | `aap jobs list --status dead --since 24h` → classify (bug, upstream, data) → replay or ticket |
| Integrity verification result | Daily | Alert-driven. A failure means the [evidence integrity runbook](../runbooks/evidence-integrity-mismatch.md). |
| Partition maintenance | Monthly (automated job; verify) | Confirm next 2 months' partitions exist and **direct grants are revoked** (`tests/database` T8 query) |
| Retention archive | Monthly | Export partitions past online retention → verify chain → detach (two-person change) |
| Trusted producer updates | On each `security-workflows` release | Merge PR to `config/trusted-producers.yaml`. Loader activates the new config version. |
| Catalogue/config release | On approved PR | Loader job → verify `config_versions` active row → spot-check evaluations |
| Key and secret rotation | Per schedule | [Key rotation runbook](../runbooks/key-rotation.md) |
| Access review export | Quarterly | Entra access review for org-wide roles. Attach the result as evidence. |
| Restore drill | 6-monthly | [Backup and restore plan §4](backup-and-restore-plan.md#4-restore-drill) |
| Dependency and image updates | Weekly (Dependabot/Renovate) | Normal PR flow. The CD verifies attestations. |

## 3. Deployment

1. Merge to `main` → CI (lint, tests, security pipeline, SBOM, provenance) → image pushed to ACR by digest.
2. CD deploys to **dev**: migration Container Apps job (Alembic `upgrade head`) → new revision → smoke tests (health, synthetic webhook with valid and invalid HMAC, one API call per role).
3. Manual approval (protected `production` environment).
4. CD **verifies the image attestation** (`gh attestation verify`), runs the migration job in prod, deploys the new revision with traffic shifted 10% → 100% after 15 minutes of healthy SLOs.
5. Rollback: shift traffic to the previous revision. Migrations are expand/contract (backward-compatible), so a code rollback needs no DB rollback.

## 4. Common procedures

### 4.1 Webhook backlog or delivery failures
Check the `aap-hook` 5xx rate and GitHub's webhook delivery log (App settings) → if the receiver was down, reconciliation (every 6h) backfills; trigger an early run: `aap reconcile github --since <outage start>`.

### 4.2 GitHub rate limiting
Symptom: `github_rate_limit_remaining` < 20% sustained, connector errors 403/429. Actions: confirm no reconciliation storm, raise backoff, reduce concurrency (`GITHUB_MAX_CONCURRENCY`), stagger schedules. Never switch to a user token.

### 4.3 Connector stale (Jira, DefectDojo, Dependency-Track, Defender, Security Hub, Sentinel)
The UI already shows a stale banner, and dependent evaluations show `error` (last known state). Check credentials (Key Vault expiry), network egress (firewall logs), and the upstream status. Fix, then trigger `aap connector sync <name>`.

### 4.4 Queue backlog
Check KEDA scaling (max replicas reached?), DB CPU, and slow handlers (traces). Temporarily raise max replicas. Investigate the slow handler.

### 4.5 Evidence rejections spike
Usually an expired pin (`UNAPPROVED_WORKFLOW_REF` after the 90-day window) or a `security-workflows` release not yet registered. Check `evidence_rejections` by reason. If it is forged-evidence attempts, see the SIEM event and [incident response](../runbooks/incident-response.md).

## 5. Escalation

Platform on-call → platform tech lead → Head of AppSec. Security incidents → [incident response runbook](../runbooks/incident-response.md) + SOC.
