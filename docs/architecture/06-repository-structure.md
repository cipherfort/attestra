# 06 — Repository Structure and the Secure Repository Contract

| | |
|---|---|
| Status | IMPLEMENTED |
| Related | [ADR-005](../../adr/ADR-005-github-primary-source-integration.md), [ADR-006](../../adr/ADR-006-github-actions-security-pipeline.md), [`schemas/repo-contract/`](../../schemas/repo-contract/), [`templates/repo-contract/`](../../templates/repo-contract/) |

## Part A: Repositories that make up the platform

| Repository | Purpose | Why separate |
|---|---|---|
| **`attestra`** (this repository) | Platform code, catalogue, config, docs, IaC for the platform | |
| **`security-workflows`** (new) | Reusable GitHub Actions workflows consumed by every application repo, released by tag and pinned by SHA | Consumers reference `org/security-workflows/.github/workflows/x.yml@<sha>`. A separate repo gives (a) its own stricter CODEOWNERS and release process, because write access here is effectively write access to every pipeline; (b) a release cadence independent of the platform; (c) a small, auditable trusted-producer surface. |
| **Earlier prototype scaffold** (historical, not used) | Dependency-Track + DefectDojo IaC | Unchanged ownership. Its three reusable workflows migrate into `security-workflows` in Phase 3 ([migration plan](05-pipeline-architecture.md#7-migration-from-the-existing-reusable-workflows)). |
| **`.github`** (org) | Org-default `SECURITY.md`, issue templates, workflow templates (starter `aap-security.yml`) | GitHub convention |

### A.1 This repository

```text
attestra/
├── README.md                     status, how to navigate, label legend
├── adr/                          ADR-001 … ADR-030 (+ index)
├── docs/
│   ├── architecture/             01 problem · 02 platform · 03 data model · 04 evidence · 05 pipeline · 06 repos
│   ├── security/                 platform security architecture + threat model, DPIA inputs
│   ├── standards/                control framework, rendered catalogue, SAMM/ASVS methodology, (Stage 3) org standards
│   ├── governance/               TOM, governance model
│   ├── guides/                   ASVS, cloud, Jira, SOC integration guides
│   ├── operations/               platform ops runbook, DR plan, backup & restore
│   ├── runbooks/                 incident, CVE emergency, evidence integrity, key rotation, app IR template
│   └── testing/                  test strategy
├── catalogue/
│   ├── controls/controls.yaml    SOURCE OF TRUTH for controls
│   └── frameworks/               SAMM ids (+ ASVS/SSDF/CSF importers' pinned sources)
├── config/                       classification, risk model, evidence types, licence policy, trusted producers
├── schemas/
│   ├── catalogue/                JSON Schema for the catalogue
│   ├── evidence/                 evidence-manifest schema (produced by security-workflows)
│   ├── repo-contract/            JSON Schemas for .security/* files
│   ├── database/                 SQL DDL (→ Alembic migrations in Phase 1)
│   └── api/                      OpenAPI 3.1 (validated; every operation carries x-permission)
├── templates/repo-contract/      files the onboarding bot proposes to app repos
├── backend/                      (Stage 7) Python package `aap`: api/, domain/, evaluators/, connectors/,
│                                 workers/, risk/, maturity/. One codebase, three entrypoints (web, hook, worker)
├── frontend/                     (Stage 8) React + TypeScript
├── infrastructure/               (Stage 11) Terraform: modules/ + envs/{dev,prod}
├── tests/                        database/, unit/, integration/, e2e/, security/ (abuse cases), performance/
├── tools/                        catalogue validator/renderer, importers
├── adoption-kit/                 programme (charter, roadmap, risks, RACI) + governance templates, a worked example
└── .github/workflows/            the platform's own CI/CD: consumes security-workflows (dogfooding)
```

Changes from the structure in the brief, and why:
- `backend/` and `workers/` are **one package with separate entrypoints**. They share domain logic (evaluators, risk model), and splitting them would duplicate it or need a third shared package.
- **`catalogue/` and `config/` are top-level.** They are governed content with their own CODEOWNERS, not code.
- The reusable `pipelines/` live in **their own repo** for the trust reasons above.

## Part B: Secure repository contract (application repos)

### B.1 Layout

```text
<app-repo>/
├── .security/
│   ├── application.yaml          REQUIRED (primary repo of an app): identity, owners, classification inputs, profile
│   ├── asvs.yaml                 REQUIRED Tier 1–3: ASVS version, target level, capability flags
│   └── threat-model/             REQUIRED Tier 1–2
│       ├── system-context.md     narrative + context diagram (mermaid)
│       ├── data-flow.md          DFD (mermaid) with trust boundaries marked
│       ├── trust-boundaries.md   boundary table: what crosses, controls at the boundary
│       ├── assets.yaml           assets, data flows (DF-nn), trust boundaries (TB-nn)
│       ├── threats.yaml          TM-nn: STRIDE category, rating, affected assets/flows
│       ├── mitigations.yaml      threat → control / ASVS req / ticket / test refs
│       └── residual-risk.yaml    threat → platform exception ID or risk ID (REFERENCES ONLY)
├── .github/
│   ├── CODEOWNERS                covers .github/workflows/ and .security/
│   └── workflows/
│       └── aap-security.yml      ONE caller workflow → org security-workflows (pinned SHA)
└── SECURITY.md                   or inherit org default from the .github repo
```

Secondary repos of the same application (libraries, IaC) contain only `.security/application.yaml` with `application_ref: APP-00042` and `role: component|iac|library`.

### B.2 What is deliberately *not* in the repo

| Brief proposed | Decision | Reason |
|---|---|---|
| `.security/exceptions.yaml` | **Rejected.** Exceptions live in the platform. | Anyone with write access to the repo could grant themselves an exception. Approval must sit outside the team's control (SoD). `residual-risk.yaml` may *reference* platform exception IDs, which the platform verifies. |
| `.security/risk.yaml` | **Rejected** as a source of risk scores | Risk priority is computed by the platform from context. Self-declared risk is C0. |
| `.security/security-requirements.yaml` | Replaced by `asvs.yaml` + platform requirement instantiation | Requirements derive from ASVS + profile. Custom requirements can be added in `asvs.yaml` (`custom_requirements`). |
| `.security/security-contact.yaml` | Merged into `application.yaml` (`security_contact`) | One fewer file to drift |
| Nine `security-*.yml` workflow files | **One** `aap-security.yml` caller | One file to pin and update (Dependabot bumps the SHA). Per-capability jobs are selected by inputs and auto-detection inside the suite. Nine files multiply drift and review load. |

### B.3 Trust level of contract files

Everything in `.security/` is **declared (C0)** until the platform verifies it:

| Declared | Verification |
|---|---|
| Owners | Resolved against Entra and GitHub teams. Unresolvable → ASC-GOV-01 fails. |
| `exposure: internal` | Cross-checked against cloud inventory (public IPs, Front Door/App Gateway, API Management) and DNS where connectors exist. A contradiction raises a finding and uses the **more exposed** value for classification. |
| `data_classification` | Cannot be verified automatically. Downgrades need approval. Values are sampled in AppSec review. |
| Capability flags (`api`, `web_frontend`) | Cross-checked with repo detection (OpenAPI files, frameworks). Missing flags raise a suggestion. |
| Threat-model mitigations | References must resolve (control key, ASVS ID, Jira key, test) |

### B.4 Schemas and templates

- [`schemas/repo-contract/application.schema.json`](../../schemas/repo-contract/application.schema.json): validated on every push by the GitHub connector, and locally via the `aap` CLI (Stage 7).
- [`templates/repo-contract/`](../../templates/repo-contract/): what the onboarding bot proposes in its PR.
- [`schemas/repo-contract/asvs.schema.json`](../../schemas/repo-contract/asvs.schema.json) and [`threat-model.schema.json`](../../schemas/repo-contract/threat-model.schema.json) with worked templates for every contract file (validated by `tools/config/validate.py`, including threat/asset/flow cross-references).
