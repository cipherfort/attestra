# ADR-008: PostgreSQL data model

**Status:** Proposed (2026-10-07)  ·  **Related:** [Data model](../docs/architecture/03-data-model.md), [`schemas/database/0001_core.sql`](../schemas/database/0001_core.sql)

## Context

The domain is highly relational (applications ↔ repos ↔ controls ↔ evidence ↔ findings ↔ components ↔ vulnerabilities). It needs strong consistency for workflow state, auditable ledgers, row-level scoping and moderate scale (tens of millions of evidence rows per year).

## Decision

- **Azure Database for PostgreSQL Flexible Server 16**, **separate** from the DefectDojo/Dependency-Track server (blast radius; fixes CS-3 for the new platform). General Purpose tier, zone-redundant HA, private access (VNet integration), Entra authentication with managed identities, **password auth disabled** for application roles.
- **Ledger + projection** modelling. Ledgers are INSERT-only by grant and guarded by trigger. High-volume ledgers are partitioned monthly.
- **Row-level security** as defence in depth behind API authorisation (ADR-013, ADR-022). The policy-relevant session settings are set per transaction by the API.
- **JSONB** for tool-specific summaries and profiles. **pg_trgm** for search. No separate search engine at this scale.
- Schema managed by **Alembic** migrations. `0001_core.sql` is the verified design baseline.

## Alternatives considered

| Option | Why not |
|---|---|
| Cosmos DB / document store | Weak at relational joins (CVE → component → SBOM → repo → app). No RLS equivalent. |
| Graph database for framework mappings | Mappings are small and relational queries suffice. One more datastore to secure. |
| Event store (full event sourcing) | Ledgers give the audit benefits without the operational complexity of a dedicated event store. |
| OpenSearch for search | Not justified below millions of searchable docs with fuzzy relevance needs. Trigram GIN covers names and titles. |
| Share the DD/DT PostgreSQL server | Blast radius and shared admin credentials (CS-3). Rejected. |

## Decision drivers

Relational integrity · RLS · operational familiarity (the team already runs PG Flexible) · managed HA/backup.

## Consequences

- Hash-chain inserts are serialised per chain. Acceptable at the design volume ([data model DM-1](../docs/architecture/03-data-model.md#9-open-design-points)).
- Partition maintenance becomes an operational job that **must** revoke direct partition grants (verified by test T8).

## Security implications

RLS fails closed (test T6). Ledgers cannot be modified by application roles (T1, T10). Superuser tampering is detected by the hash chain plus external checkpoints (ADR-016).

## Operational implications

PITR 35 days, long-term backups (ADR-026), monthly partition creation and retention detach, vacuum and index monitoring.
