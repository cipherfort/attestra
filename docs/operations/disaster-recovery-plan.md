# Disaster recovery plan

| | |
|---|---|
| Applies to | Any deployment; validate the times with a restore drill in yours |
| Decision | [ADR-026](../../adr/ADR-026-disaster-recovery.md) (written for Azure; the approach applies to any provider) |
| Suggested targets | Recovery time 4 hours (service failure), 8 hours (regional). Recovery point 15 minutes for the database; nothing lost for evidence files already acknowledged |

## 1. Scenarios

| # | Scenario | Impact | Recovery | Expected time |
|---|---|---|---|---|
| S1 | A node or zone fails | Brief interruption | Kubernetes reschedules the processes; use a highly available PostgreSQL | Minutes |
| S2 | A bad release | Errors or wrong results | Deploy the previous image if the release had no migration; otherwise restore the database from before the upgrade ([backup plan](backup-and-restore-plan.md)) | Under 1 hour |
| S3 | Wrong results from a code defect | Current control states wrong; ledgers intact (append-only) | Fix and release; the next scheduler sweep re-evaluates every application from the ledgers | 1–4 hours |
| S4 | Regional outage | Platform unavailable | Restore the database from a cross-region backup, deploy the chart in another region, fail over the evidence bucket's replica, repoint DNS | Up to 8 hours |
| S5 | Secrets lost | Integrations fail | Recover from the secret store's soft delete, or recreate credentials with the `aap bootstrap` commands ([key rotation](../runbooks/key-rotation.md)) | 1–2 hours |
| S6 | The platform is compromised | Integrity or confidentiality | [Incident response](../runbooks/incident-response.md) first; rebuild from verified release images; restore data from a point before the compromise, after the hash chain verifies | Incident-driven |
| S7 | GitHub or GitLab is down | No new evidence | Nothing to recover; connector runs catch up afterwards. Evidence may turn stale meanwhile, which is the honest state | Upstream-driven |

## 2. Roles

Incident lead: the platform operator. Decision to fail over to another region: the AppSec lead or a delegate.
Security operations are informed for S6.

## 3. Regional failover (S4)

1. Declare the incident and tell users the platform is unavailable.
2. Restore PostgreSQL from the cross-region backup in the recovery region.
3. Fail over the evidence bucket to its replica if the primary is unavailable; confirm the retention lock carried over.
4. Deploy the same release with the Helm chart, with `worker.replicas: 0` and `hook.enabled: false`, so nothing is
   ingested yet.
5. Start one worker and let a scheduler sweep verify the hash chain and re-evaluate.
6. Repoint DNS, then smoke test (health check, sign-in, Overview).
7. Re-enable the webhook receiver and the workers. Connector runs catch up on what was missed.
8. Review afterwards; fail back in a planned window.

## 4. Testing

Restore drill every 6 months ([backup plan](backup-and-restore-plan.md#3-restore-drill)); a regional failover
tabletop once a year; one full failover exercise before production use.
