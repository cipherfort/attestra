# RACI Matrix

| | |
|---|---|
| Status | DESIGNED: REQUIRES HUMAN APPROVAL at programme initiation |
| Related | [Governance model](../../governance/governance-model.md), [Target operating model](../../governance/target-operating-model.md) |

**R** Responsible (does the work) · **A** Accountable (one per row) · **C** Consulted · **I** Informed

Role keys: **CISO** · **HAS** Head of Application Security · **PO** AppSec Platform Product Owner · **PE** Platform Engineers · **ASE** AppSec Engineers · **GOV** Security Governance / GRC analyst · **DSL** Directorate Security Lead · **BO** Application Business Owner · **TO** Technical Owner · **SC** Security Champion · **CS** Cloud Security · **SOC** · **IAM** Identity administrator · **DPO** Data Protection Officer · **ENT** GitHub organization owner

Since [ADR-031](../../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md), **CS, SOC, IAM and ENT are roles held by named people on this project** (during bootstrap, time-bound), not other teams. If the organization later has such teams, they take these roles over.

## Programme and governance

| Activity | CISO | HAS | PO | PE | ASE | GOV | DSL | BO | TO | SC | CS | SOC | IAM | DPO | ENT |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Programme sponsorship and funding | A | R | C | | | C | I | | | | | | | | |
| Programme delivery and roadmap | I | A | R | C | C | C | I | | | | | | | | |
| Security policy (AppSec) | A | R | | | C | C | C | | | | | | | C | |
| Standards (Stage 3 documents) | I | A | C | C | R | C | C | | | C | C | C | | C | |
| Control catalogue content | I | A | C | C | R | C | C | | | C | | | | | |
| Risk model and SLAs | C | A | C | C | R | C | C | | | | | C | | | |
| Classification model | I | A | | | R | C | C | C | | | | | | C | |
| Governance Board operation | I | A | C | | C | R | C | | | | | | | | |
| KPI/KRI reporting packs | I | A | C | C | C | R | I | I | | | | | | | |
| DPIA for the platform | I | A | R | C | | C | | | | | | | | C | |

## Platform build and operations

| Activity | CISO | HAS | PO | PE | ASE | GOV | DSL | BO | TO | SC | CS | SOC | IAM | DPO | ENT |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Platform architecture and ADRs | | A | C | R | C | | | | | | C | C | C | | C |
| Platform build (backend, frontend, IaC) | | I | A | R | C | | | | | | | | | | |
| `security-workflows` releases | | I | A | R | C | | | | | C | | | | | |
| GitHub App install and org rulesets | | C | A | R | | | | | | | | | | | R |
| Integration bootstrap ([runbook](../../../docs/operations/integration-bootstrap.md)) | | C | A | R | | | | | | | C | C | R | | R |
| Entra app registration, groups, PIM | | C | A | R | | | | | | | | | R | | |
| Platform operations and on-call | | I | A | R | | | | | | | | C | | | |
| Platform security (threat model, pen test) | | A | C | R | R | | | | | | | C | | | |
| Evidence integrity verification | | A | I | R | C | I | | | | | | I | | | |
| Backup, restore and DR tests | | I | A | R | | I | | | | | | | | | |
| Connector config: Defender / Security Hub | | I | C | R | | | | | | | A | | | | |
| Connector config: Sentinel / Exabeam | | I | C | R | | | | | | | | A | | | |
| Jira integration config | | I | A | R | | | | | | | | | | | C |

## Application security lifecycle

| Activity | CISO | HAS | PO | PE | ASE | GOV | DSL | BO | TO | SC | CS | SOC | IAM | DPO | ENT |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Application registration and ownership | | | I | | | | C | A | R | R | | | | | |
| Classification (Tier 3/4) | | | | | C | | I | A | R | R | | | | | |
| Classification approval (Tier 1/2) | | A | | | R | | C | C | C | | | | | | |
| Onboard repo to security-workflows | | | I | C | | | | | A | R | | | | | |
| Implement required controls | | | | C | C | | I | I | A | R | | | | | |
| Threat model (Tier 1) | | | | | R | | | C | A | R | | | | | |
| Threat model (Tier 2/3) | | | | | C | | | | A | R | | | | | |
| Architecture security review | | A | | | R | | | C | C | C | C | | | | |
| Penetration test scheduling and scoping | | A | | | R | C | | C | C | C | | | | | |
| Finding triage (P3/P4) | | | | | C | | | | A | R | | | | | |
| Finding triage (P1/P2) | | I | | | R | | I | I | A | R | | | | | |
| False positive confirmation (P1/P2, second reviewer) | | | | | A/R | | | | C | C | | | | | |
| Remediation | | | | | C | | I | I | A | R | | | | | |
| Remediation verification (re-scan) | | | | R (automated) | | | | | A | I | | | | | |
| Exception request | | | | | C | | | C | A | R | | | | | |
| Exception approval | per [threshold table](../../governance/governance-model.md#4-risk-acceptance-exception-approval-thresholds) | | | | C | R (workflow) | | C (T1/2 co-sign) | I | I | | | | | |
| CVE emergency response ("who is affected?") | I | A | C | R | R | I | I | I | R | R | C | C | | | |
| SOC escalation of AppSec events | | C | | | R | | I | | I | | | A | | | |
| Cloud posture findings remediation | | | | | | | I | I | A | R | C | | | | |
| SAMM application assessment (annual) | | A | | | R | C | I | I | C | R | | | | | |
| SAMM organisational assessment | C | A | C | | R | R | C | | | | | | | | |

## Security Champions

| Activity | CISO | HAS | PO | PE | ASE | GOV | DSL | BO | TO | SC | CS | SOC | IAM | DPO | ENT |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Champion nomination | | I | | | | | A | | R | | | | | | |
| Champion training curriculum | | A | | | R | | C | | | C | | | | | |
| Champion community operation | | A | | | R | | I | | | R | | | | | |
| Champion time allocation (~10%) | | C | | | | | A | | R | | | | | | |
