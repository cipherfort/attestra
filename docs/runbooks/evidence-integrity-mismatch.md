# Evidence Integrity Mismatch Runbook

| | |
|---|---|
| Trigger | Daily verification job failure: hash-chain mismatch, a missing or extra record versus checkpoint, or a blob SHA-256 mismatch. SIEM event `evidence.integrity_failure`. |
| Severity | **P1 platform incident** until shown to be a benign defect |
| Related | [ADR-016](../../adr/ADR-016-evidence-immutability.md), [Incident response](incident-response.md) |

## 1. Immediate actions (first hour)

1. Page platform on-call and inform the Head of AppSec and the SOC.
2. **Freeze:** `INGESTION_PAUSED=true`. Disable the evaluator sweep and maturity snapshot jobs (prevents derived data built on suspect ledgers).
3. **Preserve:** note the current time as a PITR marker. Export the verification job output. Export the relevant `checkpoint.daily` events from Sentinel (the external anchor).
4. Put a banner in the UI: "Assurance data under integrity investigation. Figures may change."

## 2. Diagnose

| Check | How | Interpretation |
|---|---|---|
| Which chain and range? | Verification output: chain name, first mismatching record | Localises the problem |
| Compare with the external anchor | Sentinel `checkpoint.daily` for that chain and date vs DB | DB disagrees with Sentinel → **DB tampered or corrupted after the checkpoint** |
| Recompute the record hash with an independent implementation | Offline script on an exported row (JCS canonicalisation) | Distinguishes a code bug (canonicalisation change) from data change |
| DB audit | PostgreSQL logs / Defender for databases alerts: superuser sessions, `ALTER TABLE … DISABLE TRIGGER` | Indicates deliberate tampering |
| Recent deployments | Did a release change hashing or serialisation? | Benign-defect candidate |
| Blob mismatch | Compare blob version history (immutable versions) with the ledger digest | Storage corruption vs wrong digest recorded at ingestion |

## 3. Resolve

| Finding | Action |
|---|---|
| Code defect (e.g. canonicalisation changed) | Fix the code. **Do not rewrite hashes.** Append a `chain_annotation` record documenting the defect and the affected range. Re-verify. Unfreeze. |
| Corruption (no malicious indicator) | PITR restore to a new server at a verified point. Reconcile missing evidence from GitHub/source systems. Promote. Re-verify against Sentinel checkpoints. |
| Tampering | Treat as a security incident ([incident response](incident-response.md)): identify the actor, revoke access, restore from a verified point, re-derive projections, revoke any evidence inserted in the window, notify leadership and audit. |

## 4. Close-out

Unfreeze ingestion · reconcile from GitHub since the freeze time · rebuild projections · confirm the next daily verification passes · post-incident review · decision-log entry if any data could not be restored (with the affected applications and controls listed).
