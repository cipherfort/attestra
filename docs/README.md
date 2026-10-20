# FortProof

**Evidence-driven application security assurance.** FortProof answers one question for every application your organization runs: is it built and run securely, and what is the proof?

It judges each security control from verified evidence (what your pipelines and systems actually did), never from configuration alone. Each verdict explains itself, and the results add up to OWASP SAMM maturity and OWASP ASVS coverage.

![The overview page](assets/screenshots/overview-light.webp#only-light)
![The overview page](assets/screenshots/overview-dark.webp#only-dark)

## Start here

| | |
|---|---|
| [Tour](tour.md) | Eight screens from the demo world, with what each one shows |
| [Getting started](getting-started.md) | The platform and its demo running on your machine in about 15 minutes, with Docker only |
| [Install with Helm](install/helm.md) | Production on Kubernetes, with managed PostgreSQL and object storage |
| [Evaluate with Docker Compose](install/compose.md) | A complete evaluation stack, including sign-in through Keycloak |
| [Configure](configure/index.md) | Settings, integrations and the rules you can change |
| [User guide](guide/user-guide.md) | Daily use, role by role |

## How it works

```text
repository → security pipeline → evidence (verified) → controls → findings → risk
           → remediation → re-scan → maturity (OWASP SAMM / ASVS) → reporting
```

- **Evidence model:** where evidence comes from, how it is verified and what each confidence level (C0 to C3, M1 and M2) means. [Evidence model](architecture/04-evidence-model.md) · [the evidence type identifier](attestation/evidence/v1.md)
- **Controls and rules:** 48 controls with their proof, the tiering model, the risk model and the exception policy, all kept as YAML and changed by pull request. [Control framework](standards/control-framework.md) · [Control catalogue](standards/control-catalogue.md) · [Risk model](standards/risk-model.md)
- **Security model:** how the platform protects itself and the evidence it holds. [Security model](security/security-model.md) · [Access control](security/access-control-model.md) · [Platform threat model](security/platform-security-architecture.md)
- **Architecture:** [problem](architecture/01-problem-definition.md) · [platform](architecture/02-platform-architecture.md) · [data model](architecture/03-data-model.md) · [pipelines](architecture/05-pipeline-architecture.md) · [repositories](architecture/06-repository-structure.md) · [the project's own CI/CD](architecture/07-platform-cicd.md) · [decisions (ADRs)](../adr/README.md)

## Integrations

Every integration is optional and starts unconfigured; until one is set up, the controls that depend on it show *No evidence*, never a pass.

- [Integration bootstrap](operations/integration-bootstrap.md): source control, sign-in, ticketing, vulnerability data, cloud posture, SIEM and storage
- Guides: [GitLab](guides/gitlab-guide.md) · [Jira](guides/jira-integration-guide.md) · [SIEM and SOC](guides/soc-integration-guide.md) · [Cloud security](guides/cloud-security-integration-guide.md) · [ASVS](guides/asvs-implementation-guide.md)
- [Writing a plugin](develop/plugins.md)

## Operating it

[Operations runbook](operations/platform-operations-runbook.md) · [Backup and restore](operations/backup-and-restore-plan.md) · [Disaster recovery](operations/disaster-recovery-plan.md) · [Incident response](runbooks/incident-response.md) · [CVE emergency](runbooks/cve-emergency-response.md) · [Evidence integrity mismatch](runbooks/evidence-integrity-mismatch.md) · [Key rotation](runbooks/key-rotation.md)

## Reference

[REST API](reference/api.md) (from the [OpenAPI contract](../schemas/api/openapi.yaml)) · [Settings](reference/settings.md) · [Test strategy](testing/test-strategy.md) · [OpenSSF Best Practices answers](security/openssf-best-practices.md)

## Adopting it in your organization

The platform enforces its rules; your organization decides them. These are starting points to adapt and approve, not finished policy:

- **Standards:** [secure SDLC](standards/secure-sdlc-standard.md) · [application classification](standards/application-classification-standard.md) · [security requirements](standards/security-requirements-standard.md) · [threat modelling](standards/threat-modelling-standard.md) · [secure architecture](standards/secure-architecture-standard.md) · [security testing](standards/security-testing-standard.md) · [vulnerability management](standards/vulnerability-management-standard.md) · [SBOM](standards/sbom-standard.md) · [supply chain](standards/software-supply-chain-security-standard.md) · [exceptions](standards/security-exception-standard.md) · [evidence management](standards/evidence-management-standard.md) · [GitHub baseline](standards/github-security-baseline.md) · [pipeline security](standards/pipeline-security-standard.md) · [open source](standards/open-source-policy.md)
- **Maturity:** [SAMM assessment methodology](standards/samm-assessment-methodology.md) · [SAMM and ASVS mapping](standards/samm-asvs-mapping.md) · [KPIs and KRIs](standards/kpi-kri-catalogue.md)
- **Privacy:** [privacy assessment](security/privacy-assessment.md) · [DPIA considerations](security/dpia-considerations.md)
- **Adoption kit:** strategy, operating model, champions, data retention, RACI, risk register and rollout plan to copy and adapt. [Adoption kit](../adoption-kit/README.md)

## The project

FortProof is open source: code under Apache-2.0, documentation under CC BY-SA 4.0. [Roadmap](../ROADMAP.md) · [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) · [Backlog](roadmap/backlog/README.md) · [Source on GitHub](https://github.com/cipherfort/fortproof)
