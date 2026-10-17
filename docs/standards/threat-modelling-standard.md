# Threat Modelling Standard

| | |
|---|---|
| ID | STD-04 · Status: DRAFT, REQUIRES HUMAN APPROVAL |
| Owner | Head of Application Security |
| Kit | [`templates/repo-contract/.security/threat-model/`](../../templates/repo-contract/.security/threat-model/system-context.md) · schema [`threat-model.schema.json`](../../schemas/repo-contract/threat-model.schema.json) |
| References | OWASP Threat Modeling guidance, Threat Modeling Manifesto, STRIDE |

## 1. Purpose

Ensures design-level threats are identified, mitigated or consciously accepted, in a form that is version-controlled, reviewable and machine-checkable.

## 2. When a threat model is required

| Tier | Requirement | Review |
|---|---|---|
| 1 | Mandatory. AppSec-facilitated first model. | Independent review (M2) annually and on architecture change |
| 2 | Mandatory. Champion-led. | Independent review (M2) annually and on architecture change |
| 3 | Recommended. Lightweight (context + DFD + top threats). | Team review (M1) |
| 4 | Optional | – |

## 3. Content requirements

| ID | Requirement | Proven by |
|---|---|---|
| TMS-01 | The model shall live in `.security/threat-model/` in the application's primary repository | ASC-TM-01 (C1 structure) |
| TMS-02 | It shall contain: `system-context.md` (purpose, actors, context diagram), `data-flow.md` (DFD in Mermaid with trust boundaries as subgraphs), `trust-boundaries.md`, `assets.yaml` (assets, data flows DF-nn, trust boundaries TB-nn), `threats.yaml`, `mitigations.yaml`, `residual-risk.yaml` | Schema validation |
| TMS-03 | Threats shall use STRIDE categories (attack trees optional for complex threats, under `attack-trees/`). IDs (`TM-nn`) are stable and never renumbered. | Schema |
| TMS-04 | Every **high/critical** threat shall reference ≥ 1 resolvable mitigation (control, ASVS requirement, ticket, test) or a residual-risk entry referencing an **approved platform exception** | ASC-TM-03 |
| TMS-05 | High threats shall have abuse-case tests where feasible (Tier 1: ≥ 60% of high threats) | ASC-TST-04 |
| TMS-06 | The review shall be bound to the commit SHA of the files reviewed. Reviewers for Tier 1/2 shall be outside the owning team. | ASC-TM-01 (M2) |
| TMS-07 | The model shall be updated, and re-reviewed, when an architecture change occurs. Signals: a PR labelled `architecture-change`, changes to `data-flow.md`, new internet exposure or a new data store in `application.yaml`. | ASC-TM-02 (event-bound) |

## 4. Process

1. **Prepare** (champion): system context and DFD from current architecture.
2. **Workshop** (60–120 min, Tier 1 facilitated by AppSec): walk each data flow crossing a trust boundary, apply STRIDE, record threats with likelihood/impact/rating.
3. **Decide** for each threat: mitigate (link controls, requirements, tickets), accept (raise an exception in the platform and reference it), or transfer.
4. **Commit** the model in a PR (CODEOWNERS: security champions).
5. **Review** in the platform (records reviewer, commit SHA, outcome).
6. **Maintain** with each architecture change. Annual refresh.

## 5. Quality criteria for reviewers

Trust boundaries are explicit · every external interface appears in the DFD · authN/authZ threats considered for every boundary crossing · sensitive assets mapped to flows · mitigations are specific (not "use best practice") · residual risks have owners and expiry via exceptions.
