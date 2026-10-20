# ADR-007: Evidence storage architecture

**Status:** Accepted (2026-10-20), implemented; the Azure services named here are one deployment option since [ADR-032](ADR-032-open-source-product.md) made the product provider-neutral  ·  **Related:** ADR-016, ADR-017, [Evidence model section 6](../docs/architecture/04-evidence-model.md#6-immutability-and-audit-summary-of-adr-016)

## Context

Evidence comes as raw artefacts (SARIF, SBOMs, scanner JSON, pen-test reports; KB to ~200 MB) plus structured metadata. It must be queryable (metadata), tamper-evident, retained for years, and not deletable by administrators before retention ends.

## Decision

- **Metadata** in PostgreSQL (`evidence` ledger, ADR-008).
- **Raw artefacts** in **Azure Blob Storage** (StorageV2, private endpoint only, shared-key auth **disabled**, Entra RBAC), with:
  - container `evidence-raw`, **content-addressed** (`sha256/<aa>/<bb>/<digest>`), so identical uploads deduplicate;
  - container `evidence-manifests` for verified manifests and attestation bundles;
  - container `evidence-manual` for manual-assessment attachments (longer retention);
  - container `evidence-checkpoints` for daily hash-chain checkpoints;
  - **version-level immutability with time-based retention policies, locked** after the pilot (unlocked during the pilot so policy can still change);
  - lifecycle: cool tier at 90 days, archive tier at 365 days (raw scans only);
  - GRS replication; Defender for Storage malware scanning on `evidence-manual`.
- Writes are by the ingestion worker identity only (`Storage Blob Data Contributor` on the containers). The API identity has **read** only, and serves downloads via short-lived user-delegation SAS scoped to a single blob after an authZ check.

## Alternatives considered

| Option | Why not |
|---|---|
| Store raw artefacts in PostgreSQL (`bytea`) | Bloats the DB and backups. No WORM. Expensive. |
| AWS S3 Object Lock | Equivalent capability, but the platform is Azure-hosted (cross-cloud egress and identity complexity). |
| Azure Confidential Ledger for all evidence | Strong tamper evidence, but not designed for large blobs. **Considered for checkpoints** as an upgrade to blob checkpoints (PROPOSED, cost evaluation in Phase 4). |
| Git repository as evidence store | Rewritable history. Size limits. Wrong tool. |
| DefectDojo file attachments | No immutability. Couples evidence to a tool we may replace. |

## Decision drivers

Immutability even against admins · cost at volume · private network · simple content addressing.

## Consequences

- Locked immutability policies **cannot be shortened or removed**. Retention must be agreed before locking (ADR-017, REQUIRES HUMAN APPROVAL).
- Deleting personal data inside raw artefacts before expiry is impossible. Hence minimisation **before** storage (secret values redacted, author emails retained only in raw files under restricted access). This tension is flagged for the DPIA.

## Security implications

No public network access, no shared keys, SAS only for single blobs with a short expiry, and downloads audited. Malware scanning on human uploads.

## Operational implications

Capacity: ~50k evidence/day × ~50 KB median ≈ 2.5 GB/day before dedup, ~0.9 TB/year. Cool/archive tiers keep the cost modest. Restore-from-archive latency (hours) is acceptable for audit retrieval.
