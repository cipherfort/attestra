# Backup and Restore Plan

| | |
|---|---|
| Status | DESIGNED |
| Related | [DR plan](disaster-recovery-plan.md), [ADR-026](../../adr/ADR-026-disaster-recovery.md), [Data Retention Policy](../../adoption-kit/governance/data-retention-policy.md) |

## 1. What is backed up

| Asset | Mechanism | Frequency / RPO | Retention | Location |
|---|---|---|---|---|
| PostgreSQL | Flexible Server automated backups + WAL (PITR) | Continuous, RPO ≤ 15 min (HA) | 35 days | Geo-redundant (UK South + UK West) |
| PostgreSQL long-term | Azure Backup for PostgreSQL Flexible Server (vaulted) | Monthly | 12 months | Backup vault, GRS |
| Evidence blobs | No separate backup needed: **WORM + GRS** replication | Synchronous within region, async to pair | Per retention policy | UK South + UK West |
| Archive (Parquet exports of detached partitions) | Immutable container | Monthly | to 7 years | GRS |
| Configuration (catalogue, models) | Git (this repo) + `config_versions` table | Each change | Indefinite | GitHub + DB |
| Infrastructure | Terraform in git, remote state with versioning + soft delete | Each change | Indefinite | GitHub + state storage |
| Secrets | Key Vault soft delete (90 days) + purge protection. Re-bootstrap procedures. | — | — | Key Vault |
| Container images | ACR Premium geo-replication. Images re-buildable from git + provenance. | Each build | ACR retention policy | ACR |

**Not backed up (reconstructible):** projections (`control_states`, `evidence_current_state`, `requirement_states`) are rebuilt from ledgers; the queue tables are transient; GitHub-held data is re-fetched via reconciliation.

## 2. Restore procedures

### 2.1 Point-in-time restore (logical error)
1. Choose the restore time (before the error). Restore to a **new** server (`psql-aap-restore-<date>`). Never overwrite production.
2. Run chain verification on the restored ledgers. Compare checkpoints with Sentinel.
3. Choose one: (a) promote the restored server (repoint, migrate forward), or (b) copy specific corrected rows into projections. **Never modify ledgers.** Corrections are new ledger entries.
4. Rebuild projections (`aap rebuild projections --since <time>`).
5. Record the restore as an audited event and a decision-log entry.

### 2.2 Single evidence artefact retrieval from archive
Rehydrate the blob from the archive tier (hours) → verify SHA-256 against the ledger → serve via the standard download flow.

## 3. Backup security

Backups inherit encryption (platform-managed keys; CMK if adopted). Restore permissions are limited to platform admins via PIM. Restore actions are logged and emitted to the SIEM. Backup-vault immutability is enabled (PROPOSED).

## 4. Restore drill

| Step | Success criterion |
|---|---|
| PITR restore of prod to a scratch server (random time in the last 7 days) | Completes within 1h |
| Chain verification on restored `evidence` and `audit_events` | 100% pass. Last checkpoint matches Sentinel. |
| Projection rebuild | `control_states` identical to production at the restore time |
| Random sample of 20 evidence blobs re-hashed | 100% match |
| Teardown of the scratch server | Within 24h |

Drill results are recorded as `process.review_record` evidence for the platform's own controls.
