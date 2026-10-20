# ADR-016: Evidence immutability and tamper evidence

**Status:** Accepted (2026-10-20), implemented  ·  **Related:** ADR-007, ADR-008, [Evidence model section 6](../docs/architecture/04-evidence-model.md#6-immutability-and-audit-summary-of-adr-016)

## Context

Evidence and control history are only valuable if nobody, including platform administrators and DBAs, can silently alter them. The biggest internal incentive to tamper is inflating maturity or hiding an SLA breach.

## Decision

Defence in depth across four layers:

1. **Producer authenticity:** approved workflow SHA + Sigstore attestation + digest binding (ADR-005/006).
2. **Storage immutability:** raw artefacts and manifests in Blob containers with locked time-based retention (WORM).
3. **Ledger immutability in PostgreSQL:** INSERT-only grants for application roles; a guard trigger that blocks UPDATE, DELETE and TRUNCATE even for the table owner (verified: tests T1, T10); retention only by partition detach.
4. **Tamper evidence against superusers:**
   - `record_hash = SHA-256(prev_hash ‖ JCS(record))` per monthly chain for `evidence` and `audit_events`;
   - a **daily checkpoint** `{chain, last_hash, count, time}` written to an immutable Blob container **and** emitted to Sentinel, which is outside the platform's administrative control;
   - a **daily verification job** recomputes chains and re-hashes a random 1% of blobs. Any mismatch is a P1 platform incident and a SOC event.
5. **Configuration integrity:** the catalogue, risk model and evaluator code are loaded by git SHA and image digest. Every evaluation records them, so results are reproducible and configuration changes are visible.
6. **Corrections are additive:** revocation and supersession events, never edits.

## Alternatives considered

| Option | Why not |
|---|---|
| Rely on DB permissions only | A DBA or superuser can still alter rows undetected. |
| Azure Confidential Ledger for every record | Strong guarantees. Throughput and cost are unnecessary for full records. **Candidate for checkpoints** (ADR-007). |
| Public transparency log (Rekor) for evidence hashes | Leaks the existence and timing of internal security activity. Not appropriate for internal evidence. Attestations of *private* repos use GitHub's private Sigstore instance. |
| Blockchain | No benefit over hash chain + external anchor. |

## Decision drivers

Tamper evidence against privileged insiders · verifiability by auditors · proportionate cost.

## Consequences

The ingestion path takes a per-chain advisory lock (serialisation, acceptable at volume). Chains must be re-verified before partitions are archived.

## Security implications

The external checkpoint in Sentinel is what makes superuser tampering detectable. Sentinel must retain checkpoints at least as long as the evidence (ADR-017).

## Operational implications

Daily verification job with alerting. A runbook for "chain mismatch": freeze, snapshot, investigate, restore from PITR to compare.
