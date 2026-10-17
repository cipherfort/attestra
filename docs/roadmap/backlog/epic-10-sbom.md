# E10: SBOM

**Goal:** Current, artifact-bound SBOMs for every application, enabling honest CVE impact queries.

## F01: SBOM ingestion

### E10-F01-S01: SBOM quality gate and inventory load · M · Phase 5
- **Story:** As the platform, I want SBOMs quality-checked and loaded into the component inventory, so that CVE queries are accurate.
- **AC:** Checks: ≥ 1 component, ≥ 95% purl coverage, NTIA minimum elements. Below threshold → evidence `inconclusive` with reasons. `sboms.is_current` maintained per `scope_key` (unique partial index). Components upserted by canonical purl.
- **Security:** CycloneDX parsed with size and depth limits.
- **Tests:** Fixtures: good, empty, missing purls, huge, malformed.

### E10-F01-S02: SPDX acceptance and conversion · S · Phase 5
- **AC:** SPDX 2.3 JSON converted to CycloneDX via the selected converter. Original kept in WORM. `converted_from_spdx` reason recorded. Converter selection documented (spike).

### E10-F01-S03: Forward SBOMs to Dependency-Track and sync matches · M · Phase 5
- **AC:** Project per `app_key + scope_key`, version = commit/digest. DT processing completion awaited asynchronously (not a polling loop in CI as in the pilot workflow). Matches synced to `component_vulnerabilities`.
- **Depends on:** DT deployed (R-08).

## F02: CVE impact

### E10-F02-S01: "Which applications are affected by CVE-X?" · M · Phase 5
- **Story:** As AppSec lead during a CVE emergency, I want affected / possibly affected / not affected applications with tier, exposure, owner and deployed environments, so that response starts in minutes.
- **Technical:** `GET /vulnerabilities/{id}/affected-applications` (accepts CVE/GHSA/OSV and resolves aliases). Also `GET /components?purl=pkg:maven/org.apache.logging.log4j/log4j-core&version_range=...` for pre-CVE component searches.
- **AC:** Seeded-CVE ground-truth test passes (PS-8). Apps with stale or no SBOM appear as *possibly affected*. Response < 5 s at design scale (2M components). CSV export (audited).
- **Security:** Results scoped by the caller's RLS. Org-wide only for security roles. Export audited.
- **Tests:** Performance test at scale. Alias tests. Stale-SBOM test.

### E10-F02-S02: Licence evaluation from SBOM · S · Phase 5
- **AC:** `config/licence-policy.yaml` applied with SPDX expression semantics. Results as `scan.licence` evidence. Deny → `licence` finding.
