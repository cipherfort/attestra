# Disaster Recovery Plan

| | |
|---|---|
| Status | DESIGNED. Requires a first drill to validate times (Phase 9). |
| Decision | [ADR-026](../../adr/ADR-026-disaster-recovery.md) |
| Targets | RTO 4h (zonal/service failure), 8h (regional). RPO 15 min (database), 0 for acknowledged raw evidence. |

## 1. Scenarios

| # | Scenario | Impact | Recovery strategy | Expected time |
|---|---|---|---|---|
| S1 | Single zone failure | Possible brief interruption | PG zone-redundant HA automatic failover. Container Apps reschedules. | Minutes (automatic) |
| S2 | Bad deployment | Errors or degraded function | Traffic back to the previous revision | < 15 min |
| S3 | Data corruption / logical error (e.g. bad migration, faulty evaluator writes) | Wrong projections. Ledgers intact (append-only). | Fix code. **Rebuild projections from ledgers** (`aap rebuild projections`). If a ledger is affected (should not be possible), PITR to a new server and compare. | 1–4h |
| S4 | Regional outage (UK South) | Platform unavailable | Restore PG from geo-redundant backup in UK West. Redeploy compute via Terraform (`envs/prod-dr`). Blob GRS failover (customer-initiated) if needed. Repoint private DNS. | ≤ 8h |
| S5 | Key Vault unavailable or secrets lost | Connectors fail | Soft-delete recovery. Re-bootstrap secrets per [key rotation runbook](../runbooks/key-rotation.md). | 1–2h |
| S6 | Security compromise of the platform | Integrity/confidentiality | [Incident response runbook](../runbooks/incident-response.md) first. Rebuild from IaC and verified images. Restore data from a pre-compromise point after chain verification. | Incident-driven |
| S7 | GitHub outage | No new evidence | Nothing to recover. Reconciliation catches up. Freshness ceilings may mark evidence stale; a pause-freshness flag (admin, audited) prevents false STALE during an upstream outage. | Upstream-driven |

## 2. Roles

Incident lead: platform tech lead · Decision to fail over regionally: Head of AppSec (or delegate) · Communications: platform PO · SOC informed for S6.

## 3. Regional failover procedure (S4)

1. Declare DR (Head of AppSec). Communicate "read-only/unavailable" status.
2. `terraform apply` `infrastructure/envs/prod-dr` (pre-provisioned network, Key Vault, ACR replica). Parameter: restore point.
3. Restore PG Flexible Server from geo-backup to UK West (server name in `prod-dr` vars).
4. If the primary storage account is unavailable, initiate the storage account failover. Confirm the immutability policies persist.
5. Deploy the current image digests (geo-replicated ACR) with `INGESTION_PAUSED=true`.
6. Run **chain verification** on the restored DB, and checkpoint comparison against Sentinel's `checkpoint.daily`.
7. Repoint private DNS / Front Door origin. Smoke test.
8. Unpause ingestion. Trigger GitHub reconciliation from the last evidence time.
9. Post-incident review. Fail back when the region recovers (reverse procedure, planned window).

## 4. Testing

Restore drill 6-monthly ([backup plan](backup-and-restore-plan.md)). Regional failover tabletop annually. Full regional failover exercise once before Phase 10. Drill results are recorded as platform evidence (`process.review_record`).
