# E04: SAMM Assessment

**Goal:** Evidence-derived SAMM maturity at application and organisation level, with provenance and trend.

## F01: SAMM model import

### E04-F01-S01: Import the official SAMM model at a pinned version · M · Phase 6
- **Story:** As the catalogue owner, I want the official SAMM model (practices, streams, activities, questions, answer options) imported verbatim, so that the platform never misquotes SAMM.
- **Technical:** Importer reads the official model files from `owaspsamm/core` at a pinned commit/tag → `frameworks`/`framework_items` with `official_text`. Maps to the platform short IDs in `catalogue/frameworks/samm.yaml`.
- **AC:** All 15 practices × 2 streams × 3 levels are present, with questions and answer options. The content hash is stored. Re-import of the same version is a no-op. A new version creates a new framework row.
- **Security:** Fetched over TLS from a pinned commit. The hash is recorded.
- **Tests:** Importer tests on a vendored fixture of the model. Mapping completeness test (every short ID maps).
- **Tasks:** fetch · parse · map IDs · store · verify counts.

## F02: Maturity calculation

### E04-F02-S01: Derive answers from control states · M · Phase 6
- **Story:** As Head of AppSec, I want SAMM answers derived from control states per the methodology, so that maturity reflects observed practice.
- **Technical:** Implements [methodology §A.3](../../standards/samm-asvs-mapping.md#a3-maturity-calculation): automated fraction → banded answer, manual cap rule, provenance.
- **AC:** For a fixture app, the calculated stream/practice/function scores match hand-computed expected values. Each answer carries provenance (`automated` / `manual_m2` / `manual_m1` / `unassessed`) and the control-state IDs behind it.
- **Tests:** Golden tests. Edge cases: N/A removed from the denominator, excepted counts 0, partial pro-rata.

### E04-F02-S02: Monthly maturity snapshots · M · Phase 6
- **Story:** As security leadership, I want immutable monthly snapshots, so that trends are stable and methodology changes are visible.
- **AC:** A snapshot is written on the 1st of the month with catalogue and methodology versions. Published snapshots are read-only. A trend chart marks methodology changes.
- **Tests:** Snapshot immutability test. Methodology-change marker test.

## F03: Manual SAMM assessment

### E04-F03-S01: Manual assessment workflow for non-automatable activities · M · Phase 6
- **Story:** As an AppSec engineer, I want to run a SAMM interview capturing answers only for activities without automated coverage, so that assessments are short and focused.
- **Technical:** `assessments` (type `samm_application` / `samm_organisation`) + `assessment_answers`. The UI shows official question text and pre-fills automated answers as read-only.
- **AC:** An assessment can be planned, filled, submitted and approved (approver ≠ lead assessor). Approval creates `assessment.samm_interview` evidence (M1/M2). Manual answers exceeding automated evidence are capped and shown as such.
- **Security:** SoD. Audit events.
- **Tests:** Workflow state machine tests. Cap rule tests.

### E04-F03-S02: Organisation-level Governance assessment · S · Phase 6
- **Story:** As the governance analyst, I want an organisation-scope assessment for Governance practices, so that organisation maturity includes them.
- **AC:** Org-scope assessment stored against the organisation org unit and included in org roll-ups.
