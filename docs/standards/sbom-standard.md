# SBOM Standard

| | |
|---|---|
| ID | STD-08 · Status: DRAFT, REQUIRES HUMAN APPROVAL |
| Owner | AppSec lead |
| Related | [ADR-009](../../adr/ADR-009-sbom-standard.md), [ADR-010](../../adr/ADR-010-cyclonedx-vs-spdx.md), ASC-BLD-03 |

## 1. Purpose

Ensures every application has an accurate, current component inventory bound to what is built and deployed, so the organisation can answer "which applications are affected by CVE-X?" quickly and honestly.

## 2. Requirements

| ID | Requirement | Proven by |
|---|---|---|
| SBM-01 | A **build SBOM** shall be generated for every release artifact (container image, package, binary) in the job that builds it, bound to the artifact digest | ASC-BLD-03 |
| SBM-02 | A **source SBOM** shall be generated for every repository with dependencies on each default-branch change | ASC-BLD-03 |
| SBM-03 | Format: CycloneDX JSON ≥ 1.5. SPDX 2.3 JSON is accepted and converted. The original is retained. | Ingestion |
| SBM-04 | Quality: ≥ 1 component, ≥ 95% of components with purl, NTIA minimum elements (supplier, name, version, unique identifier, dependency relationship, author, timestamp). Below this the SBOM is *inconclusive* and does not satisfy SBM-01/02. | Quality gate |
| SBM-05 | Lockfiles shall be committed for every package ecosystem used, so SBOMs reflect resolved versions | ASC-BLD-02 params |
| SBM-06 | SBOMs are produced by the paved-road workflow and ingested by the platform. Pipelines shall not upload directly to Dependency-Track. | Trusted producers |
| SBM-07 | SBOMs are **internal evidence**, including for public repositories. Publishing an SBOM externally is a product decision recorded per release. | Open Source Policy |
| SBM-08 | VEX ("not affected") statements are PROPOSED for a later release and require AppSec approval when introduced | — |

## 3. Generation tooling (defaults, replaceable)

| Context | Tool |
|---|---|
| npm, Python, Java, Go, .NET source | cdxgen |
| Terraform | the platform's lock-file parser |
| Container images | Syft |

## 4. Freshness

Artifact-bound: valid while the digest is current/deployed, with a 90-day ceiling. Dependency-Track continuously re-matches stored SBOMs against new advisories, so no rescan is needed for new CVEs.

## 5. CVE impact query semantics

**Affected**: a current SBOM contains a vulnerable version. **Possibly affected**: no SBOM, a stale SBOM or an inconclusive SBOM. **Not affected**: a current SBOM with no match. A missing SBOM is never reported as "not affected".
