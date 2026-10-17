# Project Initiation Document (PID): Phases 0–1

| | |
|---|---|
| Version | 0.1 DRAFT |
| Date | 2026-10-07 |
| Parent | [Programme Charter](programme-charter.md) (strategic case, objectives, KPIs, benefits). This PID does not repeat them. |
| Status | REQUIRES HUMAN APPROVAL (programme owner + sponsor) |

## 1. Purpose

Defines **how** the first two phases are delivered and controlled: Phase 0 (Discovery and Governance) and Phase 1 (Architecture and Foundation). Later phases get a PID addendum at each phase gate.

## 2. Approach

- **Agile delivery inside phase gates.** Two-week sprints. Backlog in [docs/roadmap/backlog](../../../docs/roadmap/backlog/README.md). A phase gate review by the Governance Board decides go/no-go to the next phase.
- **Thin vertical slice early.** By the end of Phase 1, one real repo produces one verified SAST evidence record and one control state visible via the API. This proves the riskiest design element (pull-based verified evidence) before building breadth.
- **Design-in-repo.** Architecture, ADRs, catalogue and config live in git, change by PR and are reviewed like code.
- **Dogfooding.** The platform repo is the first onboarded repository.

## 3. Phase 0: Discovery and Governance (6 weeks)

| Work package | Products | Acceptance |
|---|---|---|
| WP0.1 Estate discovery | Repo inventory (GitHub API): languages, activity, visibility, GHAS enablement, Actions usage. Candidate application groupings. Cloud subscription/account list. | Inventory reviewed with 3 directorates. Order-of-magnitude assumption A-06 confirmed. |
| WP0.2 Assumption validation | A-01…A-08 verified (GHEC + GHAS scope, Entra, Jira edition, artifact attestations for private repos, org ruleset "require workflows" availability) | Each assumption marked confirmed/changed, with design impact noted |
| WP0.3 Governance set-up | Board ToR, membership, decision log. Sponsor sign-off of the charter. | Board meets once. Charter approved. |
| WP0.4 Catalogue and model approval | Catalogue v0.1 review. Tier model and ASVS levels. Risk model and SLAs. Retention proposal. | Decisions recorded. Catalogue → v0.2. |
| WP0.5 Integration bootstrap (project-owned, [ADR-031](../../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md)) | Create the accounts (Azure subscription/tenant, GitHub organization, Jira site, AWS account if in scope) and run the [integration bootstrap runbook](../../../docs/operations/integration-bootstrap.md); DPO (DPIA start) | Every step has a named person on the project and a date |
| WP0.6 Build-vs-buy checkpoint | Short structured comparison of 2–3 ASPM products against the must-haves (evidence model, SoD, data residency, SAMM/ASVS semantics) | Board decision recorded (ADR-001 updated) |
| WP0.7 Pilot selection | 3–5 pilot apps covering: Tier 1 internet-facing; container workload; Terraform-heavy; npm/CDK; one public open-source repo | Teams and champions agreed |
| WP0.8 Baselines | KPI/KRI baselines that can be measured now (e.g. KEV exposure via a one-off scan, current MTTR from DefectDojo if deployed) | Baseline report |

**Phase 0 gate criteria:** charter approved · decision on build vs buy · catalogue/model decisions recorded · external requests owned and dated · pilot teams committed · DPIA started.

## 4. Phase 1: Architecture and Foundation (8–10 weeks)

| Work package | Products | Acceptance |
|---|---|---|
| WP1.1 Platform IaC | Terraform: VNet-integrated Container Apps env, PG Flexible (HA, geo-backup), Blob WORM (unlocked), Key Vault, ACR, Log Analytics/App Insights, NAT/firewall rules (dev + prod) | `terraform plan` clean. Checkov clean (or exceptions recorded). Private endpoints verified. |
| WP1.2 Platform CI/CD | Lint, unit, SAST, SCA, secrets, IaC, container scan, SBOM, provenance, deploy with attestation verification | Pipeline green. Platform repo produces its own evidence. |
| WP1.3 Auth | Entra OIDC BFF, role mapping from groups, session store, CSRF | AuthZ test matrix skeleton passes |
| WP1.4 Data layer | Alembic migration from `0001_core.sql`. Partition maintenance job. Schema security tests in CI. | Tests T1–T10 in CI |
| WP1.5 Config loader | Catalogue, risk model, classification, evidence types → `config_versions` by git SHA | Validator in CI. Loader idempotent. |
| WP1.6 GitHub App (reader) + webhook receiver | App manifest, receiver with HMAC/replay, queue | Synthetic webhook test. Forged-HMAC test rejected. |
| WP1.7 Thin slice | `security-workflows` prototype `sast.yml` + `emit-evidence`, ingestion with verification, `scan.sast` evaluator, `GET /applications/{id}/controls` | One real repo shows ASC-BLD-01 `satisfied` with traceable evidence. Abuse cases AC-01/02 rejected. |
| WP1.8 Platform threat model refresh | Threat model updated against the as-built system | Reviewed by an AppSec engineer outside the platform team |

**Phase 1 gate criteria:** thin slice demonstrated end to end · abuse cases AC-01, AC-02, AC-05, AC-06 pass · platform repo onboarded to itself · no open high findings on the platform.

## 5. Organisation

| Role | Name | Responsibility |
|---|---|---|
| Sponsor | TBC (CISO) | Funding, escalation, charter approval |
| Programme owner | TBC (Head of AppSec) | Delivery accountability, Board chair |
| Product owner | TBC | Backlog, acceptance, stakeholder management |
| Tech lead | TBC | Architecture integrity, ADRs |
| Platform engineers | TBC (×2 in Phase 0–1) | Build |
| AppSec engineer | TBC | Catalogue, threat models, pilot support |
| Governance analyst | TBC | Board secretariat, RAID, reporting |

## 6. Controls

| Control | Mechanism |
|---|---|
| Progress reporting | Fortnightly highlight report (RAG, milestones, RAID changes) to the programme owner. Monthly to the Board. |
| Tolerances | Time ±2 weeks per phase. Scope: must-haves fixed, should-haves flexible. Cost ±10%. Breach → exception report to the Board. |
| Change control | Scope changes via backlog with PO approval. Architecture changes via ADR PR. Catalogue/config changes via PR + Board for mandatory items. |
| Quality | Definition of Done ([backlog README](../../../docs/roadmap/backlog/README.md#definition-of-done-global)). PR review. Security review for auth/evidence/ledger code. |
| Risk and issue management | [Risk register](../risk-register/risk-register.md) reviewed fortnightly. RAID log maintained by the governance analyst. |
| Configuration management | Git (signed commits on protected branches). Releases tagged. Config versions recorded in the platform. |

## 7. Communication plan

| Audience | What | When | Channel |
|---|---|---|---|
| Leadership | Highlight + KRIs | Monthly | Board pack |
| Engineering leads | What's coming, what's asked of teams | Monthly | Eng leads forum |
| Pilot teams | Sprint demos, feedback | Fortnightly | Demo + Teams channel |
| All engineers | Programme intro, paved road, champions call | Phase 0 end, pilot start | Town hall, intranet |
| SOC / Cloud / IAM | Integration requirements and dates | Phase 0 | Working sessions |

## 8. Handover

Each phase hands over: working software (if any), updated docs and ADRs, test evidence, an updated threat model, an updated RAID log, and backlog for the next phase.
