# ADR-026: Disaster recovery

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-007, ADR-008, ADR-025

## Context

The platform is not in the delivery critical path (gates are GitHub-native), but it **is** critical during CVE emergencies ("who is affected?") and for audit evidence. Evidence loss is unacceptable. Brief unavailability is tolerable.

## Decision

| Target | Value |
|---|---|
| RTO | 4 hours (regional failure: 8 hours) |
| RPO | 15 minutes for the database. **0 for raw evidence already acknowledged** (written to GRS storage before the ledger row commits). |

- **PostgreSQL:** zone-redundant HA (automatic zonal failover). **Geo-redundant backup enabled** for cross-region restore to the paired region (UK West). PITR 35 days. Monthly long-term backups for 12 months.
- **Blob:** GRS (or RA-GRS) with immutability policies. Customer-initiated failover documented.
- **Key Vault:** Azure-managed in-geography replication. Soft delete + purge protection. Secrets can be re-bootstrapped from the runbook if needed.
- **Compute:** stateless. Recreated by Terraform in the paired region from the same ACR (geo-replicated ACR Premium PROPOSED).
- **GitHub as a buffer:** workflow artifacts persist at least 3 days (1 day for public repos), so ingestion can catch up after an outage via reconciliation.
- **Degraded mode:** read-only UI from a restored DB with ingestion paused. CVE impact queries can fall back to Dependency-Track's portfolio search (runbook).
- **Drills:** restore drill every 6 months (PITR restore to a scratch server + chain verification), regional failover tabletop annually.

## Alternatives considered

Active-active multi-region (cost and complexity unjustified by the RTO) · single-zone with LRS (unacceptable evidence risk).

## Decision drivers

Evidence durability · proportionate availability · tested recovery.

## Consequences

Geo-redundant backup must be enabled at server creation (it cannot be added later on Flexible Server). It is in the Terraform from day one.

## Security implications

Restored environments inherit private networking and identities. A restore is an audited event. Chain verification after restore proves integrity.

## Operational implications

DR runbook and drill records (they are evidence of the platform's own controls, so they are recorded *in* the platform).
