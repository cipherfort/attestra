# ADR-017: Evidence and data retention

**Status:** Proposed (2026-10-07). **REQUIRES HUMAN APPROVAL** (records management, DPO, audit).  ·  **Related:** [Data model section 6](../docs/architecture/03-data-model.md#6-retention-strategy)

## Context

Audit and incident investigations need history ("what did we know about this vulnerability, and when?"). Retention also costs money and holds personal data (committer identities in raw artefacts, user identities in audit logs). Locked WORM policies cannot be shortened once set.

## Decision (proposed periods)

| Data | Retention | Rationale |
|---|---|---|
| Evidence records, control evaluations, audit events | 24 months online, then archive to 7 years | Covers annual audit cycles and longer investigations. 7 years aligns with common public-sector record schedules. **Confirm against the organisation's schedule.** |
| Raw scan artefacts and SBOMs | 3 years WORM | Re-analysis value declines quickly. SBOMs older than 3 years have little CVE-response value. |
| Manual assessment artefacts (pen test, architecture review) | 7 years WORM | Formal assurance records |
| Closed findings | 3 years after closure, then aggregate-only | Trend and recurrence analysis |
| Personal data of leavers in registry tables | Pseudonymised 90 days after deactivation | Minimisation. IDs retained for integrity. |
| Operational data (jobs, outbox, webhook IDs) | 7–30 days | No assurance value |

Mechanics: monthly partitions are exported to Parquet in an immutable archive container *after* chain verification, then detached. WORM policies start **unlocked** during the pilot and are locked only after approval of this ADR.

## Alternatives considered

Keep everything indefinitely (cost, minimisation conflict) · 12 months only (insufficient for audit and investigations) · per-business unit retention (complexity without benefit).

## Decision drivers

Audit needs · minimisation · cost · irreversibility of locked WORM.

## Consequences

Archive queries are slow (restore from archive tier). Leadership trend data relies on monthly snapshots, which are retained indefinitely and are small.

## Security implications

Archives inherit the same access controls. Auditor access to archives is time-bound.

## Operational implications

Monthly archive job with verification. An annual retention review.
