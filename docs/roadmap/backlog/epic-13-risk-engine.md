# E13: Risk Engine

**Goal:** Transparent, configurable, versioned prioritisation. Design: [ADR-011](../../../adr/ADR-011-vulnerability-risk-model.md), [`config/risk-model.yaml`](../../../config/risk-model.yaml).

## F01: Scoring

### E13-F01-S01: Safe expression evaluator for model rules · M · Phase 5
- **Story:** As the platform, I need rule conditions evaluated safely, so that configuration cannot execute code.
- **Technical:** CEL (e.g. `cel-python`) or an AST-allowlisted evaluator over a typed context (`app`, `finding`, `vuln`, `component`). **No `eval`.**
- **AC:** All conditions in `risk-model.yaml` compile at load time (CI). Unknown fields → load error. An injection attempt in a condition string fails to compile.
- **Tests:** Fuzzing of the expression parser. Negative tests for attribute access outside the context.

### E13-F01-S02: Risk scoring with explanation · M · Phase 5
- **AC:** Each scoring writes `finding_risk_assessments` (inputs snapshot including the EPSS value/date, model version, applied rules, L, I, score, priority, explanation). Golden tests for representative findings (KEV + internet → P1; unreachable dev dependency → lowered). Overrides only raise priority.
- **Tests:** Property tests (monotonicity: more exposure never lowers priority).

### E13-F01-S03: Manual override with second approval · S · Phase 5
- **AC:** Override requires a reason and an approver ≠ the requester. Audited. Override rate is a metric (R-17).

## F02: Intelligence feeds

### E13-F02-S01: EPSS and CISA KEV daily feeds, re-scoring · M · Phase 5
- **AC:** Daily ingest with sanity bounds (reject a > 50% drop in KEV size, schema checks). Affected open findings re-scored. Automatic changes only raise priority. Lowering happens at the weekly re-score. Feed staleness is shown in the UI.
- **Security:** TLS, expected hosts via the egress allowlist.
