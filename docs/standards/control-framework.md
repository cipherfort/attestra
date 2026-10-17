# Control Framework

| | |
|---|---|
| Status | DESIGNED: catalogue v0.1.0 REQUIRES HUMAN APPROVAL (Control Catalogue Owner: Head of AppSec) |
| Source of truth | [`catalogue/controls/controls.yaml`](../../catalogue/controls/controls.yaml) → rendered as [control-catalogue.md](control-catalogue.md) |
| Related | [SAMM/ASVS mapping](samm-asvs-mapping.md), [Evidence model](../architecture/04-evidence-model.md), [ADR-002](../../adr/ADR-002-owasp-samm-maturity-framework.md), [ADR-003](../../adr/ADR-003-owasp-asvs-requirements.md), [ADR-004](../../adr/ADR-004-evidence-driven-security-model.md) |

## 1. Design principle

> **CONTROL → TEST → EVIDENCE → RISK → REMEDIATION → RE-TEST**
>
> Every control answers: *"How will the organisation prove that this control is actually operating?"* The answer is in each control's `proof` field and is checked by the validator: a control whose required evidence confidence cannot be produced by its evidence types fails CI.

## 2. Layered model

Frameworks are **not** implemented directly. They are mapped onto one internal control catalogue, so overlapping requirements are implemented and evidenced once.

```
 ┌─────────────── Framework layer (OFFICIAL — referenced, never rewritten) ───────────────┐
 │  OWASP SAMM 2.0 activity     ASVS 5.0 requirement     NIST SSDF task     CSF 2.0 sub   │
 └───────────────▲───────────────────────▲────────────────────▲──────────────────▲────────┘
                 │ maps to (many-to-many, with "contributes to" semantics)       │
 ┌───────────────┴──────────── Internal control (ORGANISATION-SPECIFIC) ─────────┴───────┐
 │  ASC-BLD-01 "SAST executes on every change to the default branch"                     │
 │   · applicability (tier × conditions)  · objective type  · owner  · exception rules   │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ assessed by
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │  Technical requirement + Test  =  evaluator rule (versioned code) + params             │
 │   scan_executed@1 {language_coverage: all_detected, query_suite: security-extended}    │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ consumes
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │  Evidence (typed, confidence-graded, fresh/expired, hash-linked to raw artefact)       │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ produces
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │  Control state (per app × control × scope) ──▶ gap = finding (type: control_gap)       │
 │  Scan results ──▶ findings ──▶ risk priority ──▶ ticket ──▶ remediation ──▶ re-scan    │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

**Two separate questions, deliberately separated:**

1. *Is the control operating?* (e.g. SAST ran on HEAD with the right configuration.) This produces **control state**.
2. *What did it find, and is that being handled?* This produces **findings → risk → SLA**, which feed *outcome* controls (ASC-VUL-*).

A scan that finds 40 vulnerabilities is a SAST control that is **satisfied**. Penalising detection teaches teams to stop detecting ([TOM §7](../../adoption-kit/governance/target-operating-model.md#7-how-the-tom-avoids-gaming)).

## 3. Application classification model

Configuration: [`config/profiles/<profile>/classification.yaml`](../../config/profiles/generic/classification.yaml). It is transparent and two-step:

1. **Floor rules.** Any match sets a *minimum* tier. Example: internet-facing + special-category personal data → at least Tier 1.
2. **Points.** Seven dimensions (data classification, personal data, exposure, user population, business criticality, privileged integration, regulatory) are summed and mapped to a tier by threshold.

Final tier = the more critical of the two. The computation (inputs, matched rules, points, model version) is stored and shown to the owner. Tier labels, thresholds and ASVS targets are configuration, not code. **Downgrades** below the computed tier need an approved override.

The tier drives: which controls are mandatory, recommended or n/a; per-tier thresholds (approvals, query suite, pen-test frequency); the minimum evidence confidence (e.g. Tier 1 threat-model review must be independent, M2); exception maximum duration and approver; and the risk-model impact base.

## 4. Control attributes

| Attribute | Meaning |
|---|---|
| `objective_type` | **configuration**: the setting *is* the control (branch rules). **activity**: something must execute (SAST). **outcome**: a measured result (SLA compliance). **process**: a human process occurred (architecture review). |
| `applicability.tiers` | mandatory / recommended / n/a per tier |
| `applicability.conditions` | Profile facts derived from discovery + `application.yaml`: `has_source_code`, `has_iac`, `uses_dependencies`, `builds_or_deploys_containers`, `has_api`, `has_web_ui_or_api`, `deployed`, `has_cloud_scope`, `publishes_artifacts`, `has_workflows`, `has_third_party_services`, `deployed_via_github`, `has_sbom_capable_stack`, `lifecycle_retired` |
| `assessment.mode` | **automated**: no human input. **hybrid**: automated evaluation of evidence that includes a human step. **manual**: human assessment recorded in the platform. |
| `assessment.min_confidence` | Lowest evidence confidence that can satisfy the control (scalar or per tier). See the [evidence model](../architecture/04-evidence-model.md#3-confidence-levels). |
| `proof` | How operation is proven. Mandatory. |
| `exception` | Whether exceptions are allowed and their maximum duration per tier. Some controls (exposed secrets, malicious packages, registration) allow **no** exception. |

## 5. Control state model

Each `(application, control, scope)` has exactly one current state. Scope is usually a repository, sometimes an artifact or cloud scope; app-level state is the worst scope state, with per-scope drill-down.

| State | Meaning | Counts toward maturity? |
|---|---|---|
| `SATISFIED` | Fresh evidence at ≥ min confidence; rule passed | Yes |
| `PARTIAL` | Rule passed for some scopes or some criteria (e.g. 2 of 3 languages) | Pro-rata |
| `NOT_SATISFIED` | Fresh evidence shows the rule failed | No |
| `STALE` | Evidence exists but is expired or superseded | No |
| `NO_EVIDENCE` | No evidence of sufficient confidence | No |
| `EXCEPTED` | Active approved exception covers it | No (reported separately: an exception is a risk decision, not maturity) |
| `NOT_APPLICABLE` | The applicability rule says n/a, or an approved N/A justification exists | Excluded from the denominator |
| `ERROR` | The evaluator could not run (connector down) | Last known state shown, flagged |

Every transition is an append-only `control_evaluations` row: rule version, catalogue version, evidence IDs used, and a human-readable explanation, e.g. *"NOT_SATISFIED: CodeQL analysis covers python, javascript; repository also contains go (detected 2026-10-01). Evidence EV-… commit 3f2a…"*.

**Control gaps become findings.** A mandatory control in `NOT_SATISFIED`, `STALE` or `NO_EVIDENCE` for more than its grace period (default 14 days after onboarding baseline) creates a finding of type `control_gap`. It enters the same risk, SLA and Jira pipeline as vulnerabilities.

## 6. Catalogue governance

| Aspect | Rule |
|---|---|
| Change process | PR to `catalogue/` with CODEOWNERS = AppSec governance. CI runs `tools/catalogue/validate.py --check`. |
| Versioning | SemVer. Major: a new mandatory control or a stricter threshold (requires a comms plan and grace period). Minor: new recommended control or mapping. Patch: wording. |
| Grace periods | A new or stricter mandatory control starts in **observe mode** for ≥ 30 days. State is computed and shown but does not create findings or affect maturity. |
| Review | Every control is reviewed every `review_months` (default 12). The catalogue owner signs off annually. |
| Retirement | Controls are deprecated, never deleted. Historical evaluations keep their meaning. |
| Mapping integrity | SAMM streams and evidence types are validated against registries. ASVS chapter references now; requirement-level references after the official ASVS 5.0 import (E12). |

## 7. Official vs organisation-specific content

| Content | Classification | Handling |
|---|---|---|
| SAMM business functions, practices, streams, activity descriptions, questions | **Official** | Imported from the official model at a pinned version. Never paraphrased in the UI. |
| ASVS requirements and levels | **Official** | Imported from the official ASVS 5.0 release artefacts |
| SSDF tasks, CSF subcategories | **Official** | IDs only, linked to source |
| Control IDs, wording, thresholds, applicability, evidence rules, tiers, SLAs, risk model | **Organisation-specific** | This repository. Approved by the catalogue owner. |
| Mapping of internal controls to official items | **Organisation-specific judgement** | Each mapping means "provides evidence towards", never "fully satisfies" |
