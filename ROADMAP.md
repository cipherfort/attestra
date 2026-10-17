# Roadmap to 1.0

The goal of 1.0: any organization can deploy the platform on its own infrastructure, connect GitHub or GitLab, onboard a real application, and see verified evidence turn into control verdicts and prioritised findings, without help. Decision: [ADR-032](adr/ADR-032-open-source-product.md).

Estimates assume one full-time maintainer; contributors shorten them. 0.x preview releases start after M2.

| Milestone | What it delivers | Estimate | Status |
|---|---|---|---|
| **M0 Open-source foundations** | Licence, community files, CI security checks, licence gate, organization-specific content removed, documents split into product docs and an adoption kit | 2 weeks | **Done locally**, except the name, the public repository and the conduct contact (maintainer decisions) |
| **M1 Provider-neutral core** | Database baseline without GitHub/Entra-specific columns; configurable organization hierarchy and classification profiles; plugin registry and interfaces; one settings file; S3-compatible evidence store; per-process database logins | 4 weeks | **Done** (GitLab-ready schema, profiles, plugins, settings, S3/mounted secrets, per-process logins) |
| **M2 A real team can onboard** | Application registration (UI + CLI); the `aap-evidence` tool; shipped security pipelines for GitHub; built-in vulnerability feeds (OSV, CISA KEV, EPSS); exceptions, assessments and admin screens; the 9 missing control evaluators; report export; OpenAPI-generated UI types | 5 weeks | **Built and tested locally.** Outstanding: the end-to-end run on a real GitHub organization (needs an organization you create; see below) |
| **M3 GitLab** | Evidence trust spike (ADR-033), GitLab adapter (auth, webhooks, artifacts, settings), GitLab CI components, live tests against GitLab CE | 5 weeks | **Done.** Spike → [ADR-033](adr/ADR-033-gitlab-evidence-trust.md); adapter, components, webhooks/polling, GitLab Issues; tested end to end on GitLab CE with a real runner (nightly CI). Outstanding: a run against gitlab.com (needs a group you own) |
| **M4 Packaging** | Signed multi-arch images with SBOMs and provenance; Helm chart; Compose evaluate/full profiles; Azure and AWS Terraform examples; upgrade testing | 3 weeks | **Done.** Helm chart installed and upgraded on kind in CI; Compose evaluation stack run with Keycloak sign-in and RustFS Object Lock; AWS and Azure Terraform examples validated and scanned; upgrades from every earlier migration tested with data. Outstanding: the first tagged release (signed GHCR images and chart) runs when the public repository exists |
| **M5 Assurance** | Product threat model refresh, parser fuzzing, independent security review, OpenSSF Best Practices badge | 2 weeks + review | **Done in-house; external parts prepared.** Threat model refreshed (T-19…T-30); property-based fuzzing of every untrusted-input parser (found and fixed two crash classes; nightly 5,000 examples); dependency audits in CI; release-please, signed release pipeline, [RELEASING.md](RELEASING.md). REQUIRES HUMAN ACTION: commission the [independent review](docs/security/review-scope.md); request the [Best Practices badge](docs/security/openssf-best-practices.md); repository settings for Scorecard (branch protection, tag ruleset) |
| **M6 Docs and adoption kit** | Documentation site (getting started, install, configure, user and admin guides, plugin developer guide, API reference); adoption kit as templates | 3 weeks | **Done.** Docs site sections: [getting started](docs/getting-started.md), install (Helm, Compose, Terraform examples), [configure](docs/configure/index.md), [user guide](docs/guide/user-guide.md), [plugin guide](docs/develop/plugins.md) with a CI-tested [example plugin](examples/plugins/aap-plugin-jsonl/README.md), generated [settings](docs/reference/settings.md) and [API](docs/reference/api.md) reference, [security model](docs/security/security-model.md); adoption kit [templates](adoption-kit/templates/) and a 90-day playbook |
| **M7 Community** | Public roadmap, `good first issue` labels, discussions, 0.x previews | Ongoing | **Prepared:** [labels](.github/labels.yml), [seed issues](docs/roadmap/good-first-issues.md), release-please. REQUIRES HUMAN ACTION: create the public repository and enable Discussions and a Project board |
| **1.0** | Release; then an application to become an OWASP project | | |

## What works today

- **Working:** the engine, API, web UI and sign-in, and connectors for GitHub, Jira, Dependency-Track, DefectDojo, Defender for Cloud, Security Hub, Sentinel and Azure Blob. The demo and the local integration stack exercise all of these, with 241 automated tests plus 7 against real services.
- **Registration works:** a team registers its application from `.security/application.yaml` (web UI, API or `aap apps register`). Tier 1/2 waits for an AppSec engineer outside the owning team; Tier 3/4 is auto-approved; the decision becomes evidence and controls are evaluated.
- **Shipped pipelines:** nine reusable GitHub workflows (CodeQL, OSV-Scanner, gitleaks, Checkov, Syft, Trivy, zizmor, security-test and deploy evidence) with the `aap-evidence` manifest tool inlined, rendered by `aap pipelines export` and trusted by `aap pipelines approve`. They pass actionlint, shellcheck and zizmor in CI; the platform's verifier accepts what the tool writes (tested).
- **Built in, no accounts needed:** OSV, CISA KEV, FIRST EPSS and endoflife.date feeds; all 48 control evaluators; exceptions (approval matrix, co-signature, expiry); manual assessments (M1/M2); admin screens; CSV export; chat notifications.
- **Contract:** the OpenAPI document matches the implementation in both directions (test), UI types are generated from it, and Schemathesis fuzzes every implemented read operation in CI.
- **Not yet verified end to end (REQUIRES EXTERNAL CONFIGURATION):** the M2 exit test on a real GitHub organization: publish the pipelines, push to a repository, see C2/C3 evidence change control states, and a dependency finding close after the fix. It needs a throwaway organization owned by the maintainer.

## After 1.0 (not committed)

- More source control: Azure DevOps, Bitbucket.
- More ticketing: ServiceNow.
- More security systems: GCP Security Command Center, Elastic, HashiCorp Vault.
- Imports from Prowler and other scanners.
- Multi-organization (tenant) support, if adopters need it.
