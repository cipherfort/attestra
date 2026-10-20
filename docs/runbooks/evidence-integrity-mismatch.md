# Evidence Integrity Mismatch Runbook

| | |
|---|---|
| Trigger | The scheduler's hash-chain verification fails (a critical log line and the SIEM event `evidence.integrity_failure`), a record disagrees with an external checkpoint, or a file's SHA-256 disagrees with the ledger. |
| Severity | **P1 platform incident** until shown to be a benign defect |
| Related | [ADR-016](../../adr/ADR-016-evidence-immutability.md), [Incident response](incident-response.md) |

## 1. Immediate actions (first hour)

1. Page platform on-call and inform the AppSec lead and the SOC.
2. **Freeze:** stop the workers and the webhook receiver (`worker.replicas: 0` and `hook.enabled: false` in the chart, or stop those Compose services). Nothing is ingested, evaluated or snapshotted on top of a suspect ledger; the API stays up, read-only in effect.
3. **Preserve:** note the current time as a point-in-time recovery marker. Keep the worker logs with the verification failure. If a SIEM receives the daily checkpoint events, export the relevant ones: they are the external anchor.
4. Tell users that assurance data is under investigation and figures may change.

## 2. Diagnose

| Check | How | Interpretation |
|---|---|---|
| Which record? | The worker log: "evidence hash chain broken at index N of M" for the current month's chain | Localises the problem |
| Compare with the external anchor | The SIEM's `checkpoint.daily` event for that chain and date vs the database | The database disagrees with the checkpoint → **DB tampered or corrupted after the checkpoint** |
| Recompute the record hash with an independent implementation | Offline script on an exported row (JCS canonicalisation) | Distinguishes a code bug (canonicalisation change) from data change |
| DB audit | PostgreSQL logs and your database provider's alerts: superuser sessions, `ALTER TABLE … DISABLE TRIGGER` | Indicates deliberate tampering |
| Recent deployments | Did a release change hashing or serialisation? | Benign-defect candidate |
| Blob mismatch | Compare blob version history (immutable versions) with the ledger digest | Storage corruption vs wrong digest recorded at ingestion |

## 3. Resolve

| Finding | Action |
|---|---|
| Code defect (e.g. canonicalisation changed) | Fix the code. **Do not rewrite hashes.** Append a `chain_annotation` record documenting the defect and the affected range. Re-verify. Unfreeze. |
| Corruption (no malicious indicator) | PITR restore to a new server at a verified point. Missing evidence comes back as connector runs fetch it again from GitHub or GitLab. Promote. Re-verify against Sentinel checkpoints. |
| Tampering | Treat as a security incident ([incident response](incident-response.md)): identify the actor, revoke access, restore from a verified point, re-derive projections, revoke any evidence inserted in the window, notify leadership and audit. |

## 4. Close-out

Start the workers and the webhook receiver again · let connector runs catch up · confirm the next scheduler sweep verifies the chain · post-incident review · decision-log entry if any data could not be restored (with the affected applications and controls listed).
