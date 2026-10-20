# Backup and restore plan

| | |
|---|---|
| Applies to | Any deployment; validate the times with a restore drill in yours |
| Related | [Disaster recovery](disaster-recovery-plan.md) · [ADR-026](../../adr/ADR-026-disaster-recovery.md) · [Data retention policy template](../../adoption-kit/governance/data-retention-policy.md) |

Restoring the database is enough to bring the platform back. Evidence files live in write-once storage that keeps its
own versions, and everything else is in git or can be recomputed.

## 1. What to back up

| Asset | How | Suggested target |
|---|---|---|
| PostgreSQL | Your provider's point-in-time recovery (managed PostgreSQL, or CloudNativePG with WAL archiving) | Recovery point within 15 minutes; 35 days of history; monthly copies kept for 12 months |
| Evidence files | No separate backup: S3 Object Lock or Azure Blob immutability keeps every version. Add cross-region replication if you need regional resilience | As long as your retention policy requires |
| Rules (catalogue, `config/`) | Git, plus the `config_versions` table, which records every version loaded | Indefinitely |
| Settings (`aap.yaml`, Helm values) | Git | Indefinitely |
| Secrets | Your secret store (Kubernetes secrets, a mounted CSI store, or Azure Key Vault) with soft delete where it offers it; the `aap bootstrap` commands recreate integration credentials | — |
| Container images and chart | Released, signed and kept in GHCR; rebuildable from the tagged source | — |

**Not backed up, because it is recomputed:** current control states, evidence freshness and snapshots of the month in
progress (the scheduler re-evaluates every application on each sweep); the job queue; data held by GitHub or GitLab,
which connector runs fetch again.

## 2. Restore

1. Pick a point in time before the problem. Restore to a **new** database; never overwrite production.
2. Point a worker at the restored database and let one scheduler sweep run: it verifies the current month's evidence
   hash chain and re-evaluates every application. A chain failure means the
   [evidence integrity runbook](../runbooks/evidence-integrity-mismatch.md).
3. Switch the deployment to the restored database (the `database-url-*` secrets), then `helm upgrade` so the migration
   job brings it to the running version.
4. Never edit ledger tables (evidence, evaluations, finding events, audit events). A correction is a new record.
5. Record the restore in your change log; the platform's audit trail continues from the restored point.

## 3. Restore drill

Every 6 months, and before first production use:

| Step | Success criterion |
|---|---|
| Restore production to a scratch database from a random point in the last 7 days | Completes within 1 hour |
| Start a worker against it and let the scheduler sweep run | No `evidence.integrity_failure`; the hash chain verifies |
| Compare control states with production at the restore time | Identical for evidence older than the restore point |
| Fetch a few evidence files from the bucket | Their SHA-256 matches the hashes the evidence page shows |

Record the drill result; it is evidence for your own platform controls.
