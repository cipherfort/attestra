# ADR-009: SBOM as a first-class capability

**Status:** Accepted (2026-10-20), implemented; the Azure services named here are one deployment option since [ADR-032](ADR-032-open-source-product.md) made the product provider-neutral, amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Originally built on:** the earlier prototype's ADR-0001 (reference only since ADR-031)  ·  **Related:** ADR-010, control ASC-BLD-03

## Context

The platform must answer "which applications are affected by CVE-X?" quickly and honestly. That needs a current component inventory per application, bound to what is built and deployed. Dependency-Track is already chosen for continuous re-matching.

## Decision

1. **Two SBOM kinds:**
   - **Source SBOM** per repo at the default-branch commit (from lockfiles: cdxgen, plus the existing Terraform lock-file parser).
   - **Build SBOM** per release artifact, **bound to the artifact digest** (Syft for images; cdxgen in the build context for packages).
2. **Format:** CycloneDX JSON ≥ 1.5 internally (ADR-010).
3. **Minimum quality gate** at ingestion: ≥ 1 component; ≥ 95% components with purl; NTIA minimum elements present (supplier, name, version, unique ID, dependency relationship, author, timestamp). Below threshold → evidence result `inconclusive` with reasons, so it **does not satisfy ASC-BLD-03**.
4. **Platform-mediated ingestion:** verified SBOMs are forwarded to Dependency-Track by the platform (project = app key + scope key, version = commit/digest). DT's continuous matching results flow back via its API.
5. The platform keeps its **own component inventory** (`components`, `sbom_components`, `component_vulnerabilities`) for cross-application queries joined with application context. It does not rely on DT's portfolio alone.
6. **CVE query honesty:** results come back as *affected* / *possibly affected (no or stale SBOM)* / *not affected*.
7. **VEX** (CycloneDX VEX) for "not affected" statements: PROPOSED for Phase 11. It needs a governance process (who may assert not-exploitable).

## Alternatives considered

| Option | Why not |
|---|---|
| SCA scanning without SBOM retention | Point-in-time only. Cannot answer "who is affected" for a new CVE without re-scanning everything. |
| Source SBOM only | Misses OS packages and base-image components in containers, where many CVEs live. |
| GitHub dependency-graph SBOM export only | SPDX only. No Terraform. Not bound to build artifacts. |

## Decision drivers

Fast, honest CVE impact queries · artifact binding · reuse of Dependency-Track.

## Consequences

- Build pipelines must call `sbom.yml` in the job that builds the artifact. This is a team-side change that onboarding must support.
- Storage of SBOMs: ~1 MB median compressed × builds. Covered by ADR-007 tiers.

## Security implications

SBOMs reveal the attack surface. They are internal evidence even for public repos (ADR-028, "Open source" section) and are not published unless a release process explicitly decides to.

## Operational implications

Dependency-Track sizing must grow with the portfolio. The infra repo's 4 GB heap note applies. Re-size before Phase 10.
