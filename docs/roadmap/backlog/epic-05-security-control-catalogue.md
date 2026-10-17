# E05: Security Control Catalogue

**Goal:** A governed, versioned, machine-readable control catalogue that drives evaluation.

## F01: Catalogue as code

### E05-F01-S01: Catalogue review and v0.2 · M · Phase 0
- See E01-F01-S02 (Board approval). Engineering side: incorporate amendments, keep the validator green.

### E05-F01-S02: Validator and renderer in CI · M · Phase 1
- **Story:** As the catalogue owner, I want every catalogue/config PR validated and the rendered catalogue kept in sync, so that broken or unsatisfiable controls never merge.
- **Technical:** `tools/catalogue/validate.py --check` in CI. Extend checks to `config/risk-model.yaml` (expression syntax via the CEL parser), `config/profiles/<profile>/classification.yaml` and trusted producers.
- **AC:** A PR introducing an unknown evidence type, unknown SAMM stream or unreachable confidence fails CI with a clear message. A stale rendered doc fails CI.
- **Tests:** Negative fixtures for each check.
- **Stage 1 progress:** IMPLEMENTED for the catalogue (48 controls validate; it caught a real modelling error in threat-model evidence). Config validation IMPLEMENTED in `tools/config/validate.py` (trusted producers, SAMM targets, exception policy, classification, risk model, licence policy, maturity bands, ASVS applicability, templates, OpenAPI). Risk-model expression compilation pending E13-F01-S01.

## F02: Catalogue loading

### E05-F02-S01: Load catalogue and config into `config_versions` · M · Phase 1
- **Story:** As the evaluator, I need the active catalogue and config versions loaded by git SHA, so that every evaluation is reproducible.
- **Technical:** Loader job reads files at a release SHA → `config_versions` (content hash), `controls`, `control_framework_mappings`, `control_applicability`. Activation is an explicit step (one active per kind).
- **AC:** Loading the same SHA twice is a no-op. Activation is audited. Evaluations reference `catalogue_version_id`.
- **Security:** Runtime edits are impossible (no API to edit controls). Only the loader writes these tables (T-12).
- **Tests:** Loader idempotency. Activation constraint (`config_versions_one_active`).

### E05-F02-S02: Observe mode and grace periods · M · Phase 4
- **Story:** As the Board, I want new or tightened mandatory controls to start in observe mode for ≥ 30 days, so that teams see impact before it counts.
- **AC:** Controls flagged `observe_until` produce states with `observe_mode=true`, are excluded from maturity and gap findings, and are visibly labelled in the UI.

## F03: Control gap findings

### E05-F03-S01: Create `control_gap` findings after the grace period · M · Phase 4
- **Story:** As Head of AppSec, I want mandatory controls failing beyond the grace period to become findings, so that gaps enter the same SLA and ticket flow as vulnerabilities.
- **AC:** Fingerprint `gap|app|control|scope`. One finding per gap (dedup). Auto-closes when the control is satisfied (closure evidence = the satisfying evaluation). Respects active exceptions.
- **Tests:** Lifecycle tests including flapping (satisfied → not → satisfied) without duplicate findings.

### E05-F03-S02: Applicability engine · M · Phase 4
- **Story:** As the evaluator, I need to know which controls apply to an app (tier × conditions), so that teams are not asked for irrelevant controls.
- **AC:** The conditions vocabulary (control framework §4) is derived from profile + detection. Unknown conditions fail the catalogue validator. The applicability explanation is shown per control.
