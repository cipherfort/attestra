# E08: Evidence Engine

**Goal:** Collect, verify, store, age and evaluate evidence, producing explainable control states. Design: [evidence model](../../architecture/04-evidence-model.md).

**Progress (Stage 7):** F01-S01, F02-S01 (local write-once store), F02-S02 (chain + verification job; Sentinel checkpoint export pending), F03-S01, F04-S01 (39/48 evaluators), F05-S01 IMPLEMENTED with integration tests. Stage 9: connector evidence (F01-S02) and the Azure WORM blob store (F02-S01, tested on Azurite) IMPLEMENTED; Sentinel checkpoint export IMPLEMENTED. Remaining: revocation rules (F03-S02), manual evidence UI (F01-S03).

## F01: Ingestion and verification

### E08-F01-S01: Verified ingestion of workflow evidence · M · Phase 1 (thin slice) → 4
- **Story:** As the platform, I want every evidence bundle verified (approved workflow SHA, attestation, digests, binding, limits) before storing, so that forged evidence is rejected.
- **Technical:** Steps 1–6 of evidence model section 4. Rejections → `evidence_rejections` + audit + (repeated) SIEM event.
- **Depends on:** E06-F02-S03, E07-F01-S02, E05-F02-S01 (trusted producers).
- **AC:** AC-01 (hand-crafted manifest) → `UNTRUSTED_PRODUCER`. AC-02 (approved path at an unapproved SHA) → `UNAPPROVED_WORKFLOW_REF`. Digest mismatch → `DIGEST_MISMATCH`. Valid → evidence C2/C3 with `confidence_reasons`.
- **Security:** Treat every artifact as hostile: safe parsers, size limits, isolated worker identity (T-05).
- **Tests:** One negative test per reason code. Fuzzing of the manifest parser.

### E08-F01-S02: Connector evidence (C1/C3) from APIs · M · Phase 2–5
- **AC:** Each connector writes typed evidence with `producer_type=platform_connector` and the connector version. A connector failure produces no evidence (never "observed: ok").

### E08-F01-S03: Manual evidence capture with SoD · M · Phase 6
- **AC:** Forms per manual evidence type. The reviewer is taken from the session. M2 requires the reviewer to be outside the owning team (AC-04-like negative test). Attachments are stored in `evidence-manual` with malware scanning and their hash recorded.

## F02: Storage and integrity

### E08-F02-S01: WORM storage and content addressing · M · Phase 4
- **AC:** Raw files stored at `sha256/aa/bb/<digest>`. Manifests stored. Immutability policy applied (unlocked in the pilot). An overwrite or delete attempt fails (test).

### E08-F02-S02: Hash chain, daily checkpoints, verification job · M · Phase 4
- **AC:** `record_hash` computed with RFC 8785 JCS. A daily checkpoint is written to blob and emitted to Sentinel. The verification job recomputes chains and samples 1% of blobs. An injected tamper (superuser UPDATE with the trigger disabled in a test DB) is detected.
- **Tests:** Tamper-detection test is mandatory.

## F03: Freshness

### E08-F03-S01: Freshness engine · M · Phase 4
- **AC:** Implements all five policies. Commit-bound meaningful-change logic uses the compare API with path globs. Compare truncation (> 300 files) → superseded (fail safe). The hourly sweep transitions EXPIRING/EXPIRED. Every transition is written to `evidence_validity_events`.
- **Tests:** Table-driven tests per policy. Clock-controlled tests.

### E08-F03-S02: Evidence revocation · S · Phase 4
- **AC:** A revocation rule (tool + version range, or producer SHA + time window) marks matching evidence REVOKED, triggers re-evaluation and notifies owners. Audited.

## F04: Control evaluation

### E08-F04-S01: Evaluator framework + first 20 automated evaluators · M · Phase 1 (1 evaluator) → 4
- **Story:** As an app owner, I want each control's state computed with an explanation and the evidence used, so that I know exactly what to fix.
- **Technical:** Plugin interface `evaluate(app, control, scope, evidence) -> Result(state, explanation, evidence_ids, details)`. Versioned (`name@N`). Pure functions where possible. Triggered by outbox events + hourly sweep.
- **AC:** Evaluators for: registry_complete, security_policy_present, branch_protection, codeowners_coverage, security_feature_enabled, no_open_findings, repo_access_policy, scan_clean, scan_executed, sbom_current, artifact_scanned, required_check_configured_and_executing, licence_policy, environment_protection, no_static_cloud_credentials, evidence_fresh, threat_mitigation_linkage, triage_within_sla, findings_within_sla, exceptions_governed. Every state change writes `control_evaluations` + updates `control_states`.
- **Tests:** Unit tests per evaluator with fixture evidence, including the **"config file present but never ran" → NO_EVIDENCE** case for every activity control.

## F05: Data layer

### E08-F05-S01: Migrations, partitions and RLS in CI · M · Phase 1
- **AC:** Alembic baseline from `schemas/database/0001_core.sql`. A partition job creates months ahead and **revokes partition grants**. `tests/database/run.sh` runs in CI.
- **Stage 1 progress:** DDL and 12 security-property tests IMPLEMENTED and passing against PostgreSQL 16.
