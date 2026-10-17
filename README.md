# Attestra

> A [CipherFort](https://github.com/cipherfort) open-source project. The command line, settings (`AAP_*`) and database roles keep the technical prefix `aap`.

[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15625/badge)](https://www.bestpractices.dev/projects/15625)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cipherfort/attestra/badge)](https://scorecard.dev/viewer/?uri=github.com/cipherfort/attestra)

Status: **pre-release (0.x)**, not yet production-ready · [Roadmap to 1.0](ROADMAP.md)

**An open-source engine that answers one question for every application your organization runs: is it built and run securely, and what is the proof?**

Security tools each report on their own slice: a scanner here, a cloud alert there. None of them knows which application a finding belongs to, how critical that application is, which controls it must have, or whether those controls actually *ran* rather than merely being configured. This platform adds that layer:

```text
repository → security pipeline → evidence (verified) → controls → findings → risk
           → remediation → re-scan → maturity (OWASP SAMM / ASVS) → reporting
```

- **Evidence, not configuration.** A setting that says a scan should run never satisfies a control that requires it to have run. Evidence is pulled from your source control, checked against the approved pipeline version, bound to its commit and run, optionally signature-verified (Sigstore), and stored write-once in a hash-chained ledger.
- **Every verdict explains itself.** Each control state and finding priority comes with its reasons and links to the evidence behind it.
- **Risk-based priorities.** Findings are scored with context (exploited in the wild, exploit likelihood, exposure, application tier, data), with deadlines from P1 = 7 days to P4 = 180 days. Only a re-scan closes a finding; closing a ticket doesn't.
- **Rules as data.** 48 controls, the tiering model, the risk model and the exception policy are YAML files you change by pull request, and every verdict records which rule version produced it.
- **Bring your own tools, or none.** Source control, sign-in, ticketing, vulnerability data, cloud posture, SIEM and storage are integrations you choose; nothing is assumed to exist.

## Try it in 15 minutes

**With Docker only** (real sign-in through Keycloak, write-once evidence storage, the demo world):

```bash
deploy/compose/setup.sh       # then open http://localhost:8000; the script prints the demo users' password
```

**For development** (Docker, [uv](https://docs.astral.sh/uv/), Node.js 22; a persona switcher instead of sign-in):

```bash
docker run -d --name aap-demo-db --tmpfs /var/lib/postgresql/data:rw,size=512m \
  -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=aap -p 127.0.0.1:55432:5432 postgres:16-alpine
cd backend && export AAP_DATABASE_URL=postgresql+psycopg://postgres:demo@127.0.0.1:55432/aap
uv sync && uv run aap migrate && uv run aap demo seed
(cd ../frontend && npm ci && npm run build)
AAP_AUTH_MODE=dev AAP_ENV=development uv run aap api --port 8765   # open http://localhost:8765
```

Switch between people with **Viewing as** (top right) to see what each role sees. Every integration on one machine,
including GitLab CE and the scanners: [`deploy/local/`](deploy/local/README.md). Production: the
[Helm chart](charts/attestra/README.md).

## What works today, and what doesn't

| Works (tested) | Not yet (planned for 1.0) |
|---|---|
| Evidence verification, ledgers, all 48 control evaluators, risk scoring, maturity, a role-scoped API and web UI, OIDC sign-in; application registration with AppSec approval; exceptions; manual assessments; admin screens; CSV export | An end-to-end run of the shipped pipelines on a real GitHub organization (M2 exit test) |
| Shipped GitHub security pipelines with a signed evidence manifest; built-in OSV, CISA KEV, EPSS and end-of-life feeds; integrations as plugins (GitHub, Jira, Dependency-Track, DefectDojo, Defender for Cloud, Security Hub, Sentinel, chat webhooks); S3 (Object Lock), Azure Blob or disk evidence storage; one `aap.yaml`; per-process database logins | Helm chart and signed images (M4) |
| GitLab (settings, CI components, issues; evidence capped at C2, ADR-033); a Helm chart (tested on kind), a Compose evaluation stack, AWS and Azure Terraform examples | Independent security review (M5); the first signed release |

329 automated tests, plus 8 against real services (including a GitLab CE end-to-end run), an API contract fuzz test and a Helm install/upgrade on kind. Details: [ROADMAP](ROADMAP.md).

## Documentation

| If you want to… | Read |
|---|---|
| Read it all online | [cipherfort.github.io/attestra](https://cipherfort.github.io/attestra/) |
| Understand how it works | [Platform architecture](docs/architecture/02-platform-architecture.md) · [Evidence model](docs/architecture/04-evidence-model.md) · [Control framework](docs/standards/control-framework.md) |
| See every control | [Control catalogue](docs/standards/control-catalogue.md) (rendered from [`catalogue/controls/controls.yaml`](catalogue/controls/controls.yaml)) |
| Run it with real integrations | [Local integration stack](deploy/local/README.md) · [Integration bootstrap runbook](docs/operations/integration-bootstrap.md) · [Infrastructure](examples/terraform/azure/README.md) |
| Run a security programme around it | [Adoption kit](adoption-kit/README.md): charter, business case, RACI, rollout, governance |
| Understand a design choice | [Architecture decision records](adr/README.md) |
| Everything else | [Documentation index](docs/README.md) |

## Repository map

```text
backend/        Python package `aap`: domain engine, evaluators, ingestion, connectors, API, webhook receiver, worker
frontend/       React + TypeScript UI, served by the API from the same origin
catalogue/      the control catalogue and framework mappings (OWASP SAMM, ASVS)
config/         the rules as data: tiers, risk model, evidence types, trusted producers, exceptions, integrations
schemas/        database schema, OpenAPI 3.1 spec, evidence manifest, repository contract
templates/      the files a team adds to its repository to onboard
pipelines/      the shipped security pipelines and the aap-evidence manifest tool (see pipelines/README.md)
deploy/local/   every integration on one machine (Docker Compose + bootstrap script)
charts/attestra/      Helm chart (production on any Kubernetes)
deploy/compose/  evaluation stack (Docker Compose)
examples/       reference Terraform (Azure, AWS) and deployment workflows
docs/           architecture, standards, guides, operations, runbooks, roadmap backlog
adoption-kit/   programme and governance documents to adapt (a worked example)
adr/            architecture decision records
tools/          validators: catalogue, config, metrics, links, licences
```

## Contributing and security

Contributions are welcome: plugins for systems we don't support yet are a good place to start. See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, no CLA), [GOVERNANCE.md](GOVERNANCE.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

Questions and ideas: [Discussions](https://github.com/cipherfort/attestra/discussions). Bugs and feature requests: [Issues](https://github.com/cipherfort/attestra/issues).

Found a vulnerability? Please report it privately: [SECURITY.md](SECURITY.md).

## Licence

[Apache License 2.0](LICENSE). The project builds on OWASP SAMM and OWASP ASVS, which are © OWASP and licensed CC BY-SA 4.0; see [NOTICE](NOTICE).
