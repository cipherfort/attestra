# ADR-032: Release the platform as an open-source product

**Status:** Accepted (2026-10-15) · **Related:** [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md), [ROADMAP](../ROADMAP.md), [GOVERNANCE](../GOVERNANCE.md)

## Context

The platform was designed for one organization. Teams elsewhere face the same problem: their security tools cannot tell them which applications are secure, or prove it. They would need the same engine, but on their own source control, identity provider, ticketing, cloud and SIEM, and with their own organization structure and rules.

## Decision

1. **Licence: Apache-2.0**, with a NOTICE file and SPDX headers. Contributions under the Developer Certificate of Origin (no contributor licence agreement). A CI gate keeps runtime dependencies Apache-2.0 compatible (`tools/licenses/check.py`).
2. **A vendor-neutral core plus plugins.** The core is the evidence engine, rules, ledgers, evaluation, risk, maturity, API and UI. It runs with no external system configured. Source control, identity, ticketing, vulnerability intelligence, cloud posture, SIEM export, evidence storage and secrets are plugins behind interfaces.
3. **Source control: GitHub and GitLab at 1.0.** GitLab's evidence trust model gets a spike first (GitLab does not prove which shared CI component ran). The outcome becomes ADR-033.
4. **Deployment:** Docker Compose for evaluation and small organizations; a Helm chart for production on any Kubernetes. The Azure and AWS Terraform are reference examples, not the supported path.
5. **Organization model and classification become configuration** (`config/organization.yaml`, profiles): no fixed "organisation → directorate → team" hierarchy, no single country's regulations.
6. **One deployment per organization; no multi-tenancy in 1.0. No telemetry.**
7. **Governance:** a maintainer model in the project's own GitHub organization, with an application to OWASP after 1.0, once there are external users and contributors.
8. **The programme documents become an adoption kit** (`adoption-kit/`): a worked example any organization can adapt. They are not product requirements.

## Alternatives considered

| Option | Why not |
|---|---|
| AGPL-3.0 | Protects against closed SaaS forks, but many corporate legal teams block it, which slows exactly the adoption the project needs |
| Keep it internal | The design solves a common problem; the value grows with more organizations and plugins |
| GitHub only at 1.0 | Faster, but excludes GitLab organizations. Chosen against by the maintainer; the risk is managed with the M3 spike. |
| Cloud-specific Terraform as the supported path | Most maintenance, least portable |

## Consequences

- The database baseline is rewritten once before 1.0 (provider-neutral identifiers, configurable hierarchy). Nobody runs it in production yet.
- Two source-control providers need one evidence format and one verification path, so they don't diverge (`aap-evidence` tool).
- The roadmap to 1.0 is about 24 person-weeks ([ROADMAP](../ROADMAP.md)).

## Security implications

- Publishing the code also publishes the evidence verification logic. That is intended: the trust model must not depend on secrecy.
- A private vulnerability reporting process ([SECURITY.md](../SECURITY.md)), signed releases and an independent review before 1.0 are part of the plan.
