# ADR-001: Platform purpose and scope

**Status:** Accepted (2026-10-20), implemented  ·  **Deciders:** AppSec lead, CISO  ·  **Related:** [Problem definition](../docs/architecture/01-problem-definition.md), the earlier prototype scaffold ADR-0001

## Context

The organisation has security tools: GHAS Enterprise (licensed), Checkov, Defender, Sentinel, and a scaffolded but undeployed Dependency-Track + DefectDojo. It has no application inventory, no testable control model, no retained evidence and no defensible maturity measure. Leadership wants SAMM-based maturity. Engineering wants fewer tools and less noise. Audit wants evidence.

## Decision

Build an **Application Security Assurance Platform**: an **assurance layer** whose core is the **Control + Evidence + Risk + Maturity engine**. It integrates existing tools rather than replacing them.

**In scope:** application registry and classification; internal control catalogue mapped to SAMM/ASVS/SSDF/CSF; reusable security workflows (paved road); evidence collection, verification and immutable storage; control evaluation; contextual risk prioritisation and SLA; exceptions; Jira integration; SBOM inventory queries; SAMM/ASVS maturity derivation; role-based reporting; curated SOC events.

**Out of scope:** running scanners inside the platform (pipelines run them); replacing GHAS, Dependency-Track or DefectDojo; general GRC (non-software risk, policy attestation for staff); runtime protection (WAF/RASP); a single composite "security score"; individual developer performance measurement.

## Alternatives considered

| Option | Why not chosen |
|---|---|
| Commercial ASPM product | Credible for aggregation and prioritisation. Weaker on SAMM/ASVS evidence semantics and evidence immutability. Per-repo pricing scales with the estate. Finding data leaves the tenant. **Re-evaluate at Phase 0 exit** with a short market scan against this design's requirements (evidence model, SoD, data residency), because building is a multi-year commitment. |
| Extend DefectDojo (product metadata, custom fields, benchmarks) | DefectDojo is a finding manager. Bolting on a registry, evidence ledger and control evaluation would fork a large upstream codebase and fight its data model. We keep it for what it does well. |
| Backstage software catalogue as the registry | Good ownership model, but not in use here. Adopting a developer portal is a bigger decision than this programme. **Integration path kept:** import `catalog-info.yaml` if Backstage is adopted later. |
| SAMM Toolbox spreadsheet | This is the status quo problem. Self-assessed and unverifiable. |
| Do nothing beyond the infra-repo scaffold | Covers SCA visibility only. Answers none of the ownership, control, evidence or maturity questions. |

## Decision drivers

Evidence integrity and explainability · reuse of licensed and scaffolded tools · cost that does not scale per repo · data stays in the organisation's tenant · incremental delivery (value at pilot, not after 18 months).

## Consequences

- We own a product: a team of ~4 platform engineers plus a PO, with an operations burden ([TOM](../adoption-kit/governance/target-operating-model.md)).
- Integrations are first-class work, and connector health becomes an SLO.
- Clear boundaries prevent scope creep into GRC and runtime security.

## Security implications

The platform aggregates the organisation's exploitable weaknesses, so it is classified **Tier 1** and onboarded to itself ([platform security architecture](../docs/security/platform-security-architecture.md)).

## Operational implications

On-call for platform availability during CVE emergencies (RTO 4h). Connector maintenance as upstream APIs change.
