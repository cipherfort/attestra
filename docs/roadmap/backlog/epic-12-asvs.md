# E12: ASVS

**Goal:** ASVS 5.0 operational: imported, scoped per app, verified by evidence. Design: [methodology Part B](../../standards/samm-asvs-mapping.md#part-b-owasp-asvs-operational-not-a-checklist).

## F01: Import

### E12-F01-S01: Import ASVS 5.0 from official release artefacts · M · Phase 6
- **AC:** All requirements with level and chapter/section imported verbatim, version pinned, content hash stored. Chapter list verified against the release (V1–V17). Re-import is idempotent.
- **Tests:** Importer on a vendored release fixture. Count check.

## F02: Applicability

### E12-F02-S01: `asvs.yaml` schema and capability applicability mapping · M · Phase 6
- **Technical:** `schemas/repo-contract/asvs.schema.json`. `catalogue/frameworks/asvs-applicability.yaml` (requirement/section → capability tags), maintained by AppSec.
- **AC:** For a pilot app profile, the applicable set is computed and instantiated into `security_requirements`. N/A requests need a justification (AppSec approval for Tier 1). Target level ≥ tier target is enforced (ASC-REQ-01).
- **Progress:** `asvs.schema.json`, template and chapter-level applicability map IMPLEMENTED. Section-level mapping awaits the official import (E12-F01-S01).

## F03: Verification

### E12-F03-S01: Requirement status from evidence · M · Phase 6
- **AC:** Status rules per method table (tests → VERIFIED; scanner silence → SCANNED_NO_ISSUES; finding with mapped CWE → FAILED; M2 review → VERIFIED time-bound). Nobody can set VERIFIED by hand. ASC-REQ-02 computes verified %.
- **Tests:** Per-method tests, including "scanner silence never yields VERIFIED".

### E12-F03-S02: CWE ↔ ASVS 5.0 mapping for scanner rules · S · Phase 6
- **AC:** Mapping file versioned. Coverage report of which ASVS requirements have any automated method. Reviewed by AppSec.
