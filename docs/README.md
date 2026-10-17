# Documentation Index

All documents are drafts until approved. Status labels follow the [root README](../README.md). Approval decisions are tracked in the [decision log](../adoption-kit/governance/decision-log.md).

## The 40 programme documents (brief section 31)

| # | Document | Location |
|---|---|---|
| 1 | Programme Charter | [adoption-kit/programme/charter/programme-charter.md](../adoption-kit/programme/charter/programme-charter.md) |
| 2 | Business Case | [adoption-kit/programme/charter/business-case.md](../adoption-kit/programme/charter/business-case.md) |
| 3 | Project Initiation Document | [adoption-kit/programme/charter/project-initiation-document.md](../adoption-kit/programme/charter/project-initiation-document.md) |
| 4 | Security Strategy | [governance/appsec-strategy.md](../adoption-kit/governance/appsec-strategy.md) |
| 5 | Target Operating Model | [governance/target-operating-model.md](../adoption-kit/governance/target-operating-model.md) |
| 6 | Current State Assessment | [governance/current-state-assessment.md](../adoption-kit/governance/target-state-assessment.md) (+ [problem definition](architecture/01-problem-definition.md)) |
| 7 | Target State Assessment | [governance/target-state-assessment.md](../adoption-kit/governance/target-state-assessment.md) |
| 8 | SAMM Assessment Methodology | [standards/samm-assessment-methodology.md](standards/samm-assessment-methodology.md) (process) + [standards/samm-asvs-mapping.md](standards/samm-asvs-mapping.md) (calculation) |
| 9 | Secure SDLC Standard | [standards/secure-sdlc-standard.md](standards/secure-sdlc-standard.md) |
| 10 | Application Classification Standard | [standards/application-classification-standard.md](standards/application-classification-standard.md) |
| 11 | Security Requirements Standard | [standards/security-requirements-standard.md](standards/security-requirements-standard.md) |
| 12 | Threat Modelling Standard | [standards/threat-modelling-standard.md](standards/threat-modelling-standard.md) |
| 13 | Secure Architecture Standard | [standards/secure-architecture-standard.md](standards/secure-architecture-standard.md) |
| 14 | Security Testing Standard | [standards/security-testing-standard.md](standards/security-testing-standard.md) |
| 15 | Vulnerability Management Standard | [standards/vulnerability-management-standard.md](standards/vulnerability-management-standard.md) |
| 16 | SBOM Standard | [standards/sbom-standard.md](standards/sbom-standard.md) |
| 17 | Software Supply Chain Security Standard | [standards/software-supply-chain-security-standard.md](standards/software-supply-chain-security-standard.md) |
| 18 | Security Exception Standard | [standards/security-exception-standard.md](standards/security-exception-standard.md) |
| 19 | Evidence Management Standard | [standards/evidence-management-standard.md](standards/evidence-management-standard.md) |
| 20 | Security Champions Framework | [governance/security-champions-framework.md](../adoption-kit/governance/security-champions-framework.md) |
| 21 | GitHub Security Baseline | [standards/github-security-baseline.md](standards/github-security-baseline.md) |
| 22 | Pipeline Security Standard | [standards/pipeline-security-standard.md](standards/pipeline-security-standard.md) |
| 23 | ASVS Implementation Guide | [guides/asvs-implementation-guide.md](guides/asvs-implementation-guide.md) |
| 24 | Cloud Security Integration Guide | [guides/cloud-security-integration-guide.md](guides/cloud-security-integration-guide.md) |
| 25 | Jira Integration Guide | [guides/jira-integration-guide.md](guides/jira-integration-guide.md) |
| 26 | SOC Integration Guide | [guides/soc-integration-guide.md](guides/soc-integration-guide.md) |
| 27 | Data Retention Policy | [governance/data-retention-policy.md](../adoption-kit/governance/data-retention-policy.md) |
| 28 | Access Control Model | [security/access-control-model.md](security/access-control-model.md) |
| 29 | Incident Response Runbook | [runbooks/incident-response.md](runbooks/incident-response.md) (+ [CVE emergency](runbooks/cve-emergency-response.md), [evidence integrity](runbooks/evidence-integrity-mismatch.md), [app template](runbooks/application-incident-runbook-template.md)) |
| 30 | Platform Operations Runbook | [operations/platform-operations-runbook.md](operations/platform-operations-runbook.md) (+ [key rotation](runbooks/key-rotation.md)) |
| 31 | Disaster Recovery Plan | [operations/disaster-recovery-plan.md](operations/disaster-recovery-plan.md) |
| 32 | Backup and Restore Plan | [operations/backup-and-restore-plan.md](operations/backup-and-restore-plan.md) |
| 33 | Threat Model (platform) | [security/platform-security-architecture.md section 4](security/platform-security-architecture.md#4-threat-model-the-platform-stride) |
| 34 | Privacy / Data Protection Assessment | [security/privacy-assessment.md](security/privacy-assessment.md) |
| 35 | DPIA considerations | [security/dpia-considerations.md](security/dpia-considerations.md) |
| 36 | Risk Register | [adoption-kit/programme/risk-register/risk-register.md](../adoption-kit/programme/risk-register/risk-register.md) |
| 37 | RAID Log | [adoption-kit/programme/raid/raid-log.md](../adoption-kit/programme/raid/raid-log.md) |
| 38 | RACI | [adoption-kit/programme/raci/raci.md](../adoption-kit/programme/raci/raci.md) |
| 39 | KPI/KRI Catalogue | [docs/standards/kpi-kri-catalogue.md](standards/kpi-kri-catalogue.md) (rendered from [`config/metrics.yaml`](../config/metrics.yaml)) |
| 40 | Implementation Roadmap | [adoption-kit/programme/roadmap/roadmap.md](../adoption-kit/programme/roadmap/roadmap.md) |

## Other design documents

| Area | Documents |
|---|---|
| Architecture | [01 Problem](architecture/01-problem-definition.md) · [02 Platform](architecture/02-platform-architecture.md) · [03 Data model](architecture/03-data-model.md) · [04 Evidence](architecture/04-evidence-model.md) · [05 Pipeline](architecture/05-pipeline-architecture.md) · [06 Repositories](architecture/06-repository-structure.md) · [07 Platform CI/CD](architecture/07-platform-cicd.md) |
| Controls and frameworks | [Control framework](standards/control-framework.md) · [Control catalogue](standards/control-catalogue.md) · [Risk model](standards/risk-model.md) · [Open Source Policy](standards/open-source-policy.md) |
| Governance | [Governance model](../adoption-kit/governance/governance-model.md) · [Decision log](../adoption-kit/governance/decision-log.md) |
| Integrations and infrastructure | [Integration bootstrap runbook](operations/integration-bootstrap.md) · [Infrastructure as code](../examples/terraform/azure/README.md) · [Local integration stack](../deploy/local/README.md) · [ADR-031](../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) |
| Testing | [Test strategy](testing/test-strategy.md) |
| API | [`schemas/api/openapi.yaml`](../schemas/api/openapi.yaml) (OpenAPI 3.1) |
| Decisions | [ADR index](../adr/README.md) |
| Delivery | [Backlog](roadmap/backlog/README.md) |
