# Implementation Backlog

| | |
|---|---|
| Status | Initial backlog (Stage 1). Refined each sprint by the PO. Stories become Jira issues once the Jira project exists (an import script is part of E01). |
| Hierarchy | **Epic → Feature → Story → Task → Acceptance criteria** |
| IDs | `E07-F02-S03` = Epic 7, Feature 2, Story 3. IDs are stable and never reused. |
| Priority | **M** must (pilot-critical) · **S** should · **C** could · **W** won't (this release) |
| Phase | Roadmap phase (0–11) in which the story is planned |

## Story template

Each story has: **description** (user story), **value**, **technical requirements**, **dependencies**, **acceptance criteria** (Given/When/Then or checklist), **security considerations**, **test requirements**, **tasks**, and story-specific **DoD additions** where the global DoD is not enough.

## Definition of Done (global)

A story is done only when **all** of these hold:

1. Code merged to `main` via PR with ≥ 1 review (≥ 2 for `auth/`, `evidence/`, `ledger/`, `catalogue/`, `config/`, `security-workflows`).
2. Unit tests written. Domain-module coverage does not decrease (target ≥ 85% on `domain/`, `evaluators/`, `risk/`).
3. Integration tests updated where the story touches the DB, a connector or the queue.
4. **The platform's own security pipeline is green**: SAST, SCA, secrets, IaC, container scan, SBOM, provenance. No new high/critical findings without an approved exception.
5. **AuthZ:** every new endpoint has a permission annotation and rows in the authZ test matrix (allowed and denied cases).
6. API changes reflected in OpenAPI. Spectral lint and oasdiff clean (no unannounced breaking change).
7. Logs contain no secrets or finding detail (redaction test passes). Audit events emitted for state-changing actions.
8. Docs updated (user-facing, runbook if operational, ADR if a decision changed).
9. Deployed to `dev` and verified by the PO against the acceptance criteria.
10. Threat model reviewed if the story adds a trust boundary, data store, external integration or privilege.

## Epics

| Epic | Title | Phase(s) | Stories | File |
|---|---|---|---|---|
| E01 | Programme Governance | 0 → | 5 | [epic-01](epic-01-programme-governance.md) |
| E02 | Application Discovery | 0–2 | 4 | [epic-02](epic-02-application-discovery.md) |
| E03 | Application Registry | 2 | 6 | [epic-03](epic-03-application-registry.md) |
| E04 | SAMM Assessment | 6 | 5 | [epic-04](epic-04-samm-assessment.md) |
| E05 | Security Control Catalogue | 0–1, 4 | 6 | [epic-05](epic-05-security-control-catalogue.md) |
| E06 | GitHub Integration | 1–3 | 6 | [epic-06](epic-06-github-integration.md) |
| E07 | Security Pipelines | 1, 3 | 10 | [epic-07](epic-07-security-pipelines.md) |
| E08 | Evidence Engine | 1, 4 | 9 | [epic-08](epic-08-evidence-engine.md) |
| E09 | Vulnerability Management | 5 | 6 | [epic-09](epic-09-vulnerability-management.md) |
| E10 | SBOM | 3, 5 | 5 | [epic-10](epic-10-sbom.md) |
| E11 | Threat Modelling | 4–6 | 4 | [epic-11](epic-11-threat-modelling.md) |
| E12 | ASVS | 6 | 4 | [epic-12](epic-12-asvs.md) |
| E13 | Risk Engine | 5 | 4 | [epic-13](epic-13-risk-engine.md) |
| E14 | Jira Integration | 8 | 5 | [epic-14](epic-14-jira-integration.md) |
| E15 | Cloud Integration | 8 | 4 | [epic-15](epic-15-cloud-integration.md) |
| E16 | Dashboard | 7 | 8 | [epic-16](epic-16-dashboard.md) |
| E17 | Security Champions | 2 → | 4 | [epic-17](epic-17-security-champions.md) |
| E18 | SOC Integration | 8 | 3 | [epic-18](epic-18-soc-integration.md) |
| E19 | Platform Security | 1 → | 8 | [epic-19](epic-19-platform-security.md) |
| E20 | Operations | 1, 9–11 | 6 | [epic-20](epic-20-operations.md) |
| E21 | Documentation | 0 → | 4 | [epic-21](epic-21-documentation.md) |
| E22 | Testing | 1 → | 7 | [epic-22](epic-22-testing.md) |
| E23 | Production Rollout | 9–10 | 5 | [epic-23](epic-23-production-rollout.md) |
| E24 | Integrations from zero (ADR-031) | 1–8 | 12 | [epic-24](epic-24-integrations-from-zero.md) |
| | **Total** | | **140** | |

**Already done in Stage 1** (design-verification, not production code): catalogue validator/renderer (`tools/catalogue/validate.py`; E05-F01-S02 partially), schema DDL + security-property tests (`tests/database/`; E08-F05-S01 partially), application.yaml schema + template (E03-F01-S01 partially). They are marked in the epic files.
