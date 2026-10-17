# ADR-004: Evidence-driven security model

**Status:** Proposed (2026-10-07)  ·  **Related:** [Evidence model](../docs/architecture/04-evidence-model.md), [Control framework](../docs/standards/control-framework.md)

## Context

Security assurance today is asserted, not demonstrated. The programme principle is **CONTROL → TEST → EVIDENCE → RISK → REMEDIATION → RE-TEST**. The brief also requires that the platform "never falsely claim that a control is satisfied merely because a repository contains a configuration file".

## Decision

1. Every control defines **how its operation is proven** (`proof`), the **evidence types** that can prove it, and the **minimum evidence confidence** (C0–C3, M1–M2).
2. **Confidence levels** distinguish declared (C0), configured (C1), executed (C2), attested/authoritative (C3), manual-self (M1) and manual-independent (M2) evidence. **C0 never satisfies a control.** Activity controls need ≥ C2.
3. **Control state** (`satisfied`, `partial`, `not_satisfied`, `stale`, `no_evidence`, `excepted`, `not_applicable`, `error`) is computed by versioned evaluators. Every transition records the evidence IDs and an explanation.
4. **Operation and outcome are separated.** A scan that finds issues is an operating control. Findings drive separate outcome controls (SLA).
5. **Evidence expires** under configurable freshness policies (continuous, commit-bound, artifact-bound, time-bound, event-bound).
6. Catalogue CI rejects any control whose required confidence is unreachable from its evidence types.

## Alternatives considered

| Option | Why not |
|---|---|
| Questionnaire-based assessment | Unverifiable. Stale on completion. The problem being solved. |
| Configuration-presence checks (Scorecard-style) only | Proves configuration, not operation. Explicitly prohibited by the brief for activity controls. |
| Findings-only posture ("no criticals = secure") | Rewards not scanning. Says nothing about design, process or coverage. |
| Binary pass/fail without confidence | Hides the difference between "a reviewer checked this" and "a team said so". |

## Decision drivers

Truthfulness · auditability · resistance to gaming · explainability.

## Consequences

- More engineering in evaluators and verification than a dashboard would need. That is where the value is.
- Some controls will honestly show `no_evidence` for a long time (e.g. Governance), which keeps maturity numbers lower than a questionnaire would.
- Requires stable producer identity, which is why ADR-005 and ADR-006 exist.

## Security implications

Evidence forgery becomes the main attack on the model. It is addressed by producer verification, attestation and immutability (ADR-016).

## Operational implications

Evaluators are code with unit tests and calibration audits (5% sample quarterly). Revocation of evidence is an operational procedure.
