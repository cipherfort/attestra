# E16: Dashboard (presentation layer)

**Goal:** Role-appropriate, explainable views. **No single composite security score.** Every number is drillable to evidence.

**Progress (Stage 8):** portfolio, application scorecard, evidence chain viewer, finding detail with actions, CVE impact and leadership views IMPLEMENTED against the demo (`frontend/`). Stage 9: Entra/OIDC BFF sign-in and sign-out, CSRF handling and the Integrations page IMPLEMENTED. Report packs remain.

## F01: Foundations

### E16-F01-S01: Frontend skeleton, BFF auth, design system · M · Phase 7
- **AC:** React + TS (Vite). Generated API client. Session via BFF. Strict CSP (no inline script). Accessible components (WCAG 2.2 AA target). Light/dark theme. "Data as of" + connector staleness banner component.
- **Security:** No tokens in the browser. All scanner-provided text rendered as text (AC-08 test).

### E16-F01-S02: Align the OpenAPI contract with the implemented API; generate client types · M · Phase 7
- **Why:** response shapes in `schemas/api/openapi.yaml` drift from the implemented thin-slice API (operation ids and permissions already match and are tested). The UI currently uses hand-written types (`frontend/src/api.ts`).
- **AC:** Schemathesis contract tests pass against the running API. UI types are generated from the spec. oasdiff in CI.

## F02: Persona views

### E16-F02-S01: Application scorecard (engineer / owner) · M · Phase 7
- **Story:** As an engineer, I want my app's control states, findings by priority, SLA status, evidence freshness and "what to fix next", so that I can act without reading docs.
- **AC:** Panels: tier with "why", control coverage by domain (satisfied / gaps / stale / excepted), ASVS status, findings (P1–P4, SLA), SBOM status, pipeline capability status (SAST, SCA, DAST, secrets, IaC, container), threat model and architecture review status, exceptions, evidence freshness. Each item links to its explanation and evidence chain.

### E16-F02-S02: Evidence chain viewer · M · Phase 7
- **AC:** From any control state: evaluation → evidence records (confidence, producer, tool, commit/digest, attestation) → raw artefact download (audited, short-lived SAS) → hash.

### E16-F02-S03: Team / champion work queue · M · Phase 7
- **AC:** Triage queue (new P1–P3), FP requests awaiting a second reviewer, expiring evidence and exceptions, onboarding to-dos.

### E16-F02-S04: Business unit view · M · Phase 7
- **AC:** Distribution of control coverage and maturity across apps (box plots, not league tables), SLA performance, gaps by control, exceptions due, unmanaged suppressions. Anonymised org comparison (ADR-022).

### E16-F02-S05: Security leadership and executive views · M · Phase 7
- **AC:** Leadership: maturity trend with evidence mix, KPIs/KRIs, top risks (KEV exposure, P1 overdue), coverage, programme progress. Executive: one page (coverage, % Tier 1 at target, KEV exposure trend, SLA trend), aggregates only (the `executive` role cannot drill to findings).

## F03: Reporting

### E16-F03-S01: Report packs (PDF/CSV) · S · Phase 7
- **AC:** Monthly business unit and leadership packs generated from snapshots. Exports audited (`data.bulk_export`).
