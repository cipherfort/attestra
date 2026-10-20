# ADR-031: The project creates and owns every integration it depends on

**Status:** Accepted (2026-10-20), implemented · **Amends:** [ADR-005](ADR-005-github-primary-source-integration.md), [ADR-006](ADR-006-github-actions-security-pipeline.md), [ADR-009](ADR-009-sbom-standard.md), [ADR-014](ADR-014-authentication-architecture.md), [ADR-018](ADR-018-jira-integration.md), [ADR-019](ADR-019-cloud-integration.md), [ADR-020](ADR-020-siem-integration.md), [ADR-025](ADR-025-deployment-model.md), [ADR-030](ADR-030-build-provenance-and-artifact-integrity.md) · **Runbook:** [integration bootstrap](../docs/operations/integration-bootstrap.md)

## Context

The design assumed that other teams would provide access: GitHub organization owners would install an App, an IAM team would register Entra applications, a SOC would create Sentinel collection rules, a cloud team would grant reader roles, and an existing scaffold (the earlier prototype scaffold) would provide Dependency-Track and DefectDojo. This is a fresh project. None of those systems, teams or grants exist, and nothing should be built on the assumption that they will.

## Decision

1. **Every external system the platform uses is created by this project, as code, and owned by the project team.** Nothing is pre-provisioned and nothing depends on another team.

   | System | Created by | One-time human step (a project role, see RACI) |
   |---|---|---|
   | Azure platform (network, identities, Key Vault, PostgreSQL, WORM storage, registry, Container Apps) | `examples/terraform/azure/envs/azure` (module `platform`) | Subscription Owner runs `terraform apply` |
   | Entra ID app registrations, app roles, role groups, federated credential | module `entra` | Application Administrator + Groups Administrator runs the same apply |
   | Microsoft Sentinel, custom table, DCE/DCR, analytics rules | module `sentinel` | (same apply) · SOC lead approves the event list |
   | Dependency-Track and DefectDojo (pinned versions) | module `scanners` | `aap bootstrap dependency-track` / `defectdojo` inside the VNet |
   | Defender for Cloud read access | module `azure-reader` | User Access Administrator on the chosen scopes |
   | AWS Security Hub read access (no keys) | `examples/terraform/azure/envs/aws` | AWS admin of the aggregation account |
   | GitHub `security-workflows` repo, rulesets, team, Actions policy | `examples/terraform/azure/envs/github` | Organization owner |
   | GitHub App (read-only) | `aap bootstrap github-app` (manifest flow) | Organization owner clicks "Create", then installs it |
   | Jira project and service token | `aap bootstrap jira` | Jira site admin creates the API token |
   | Platform image and release | `Dockerfile`, `.github/workflows/release.yml` (GitHub OIDC → deploy identity) | Environment reviewers approve production |

2. **Credentials are created by the bootstrap commands and live only in Key Vault** (the 0600 dev store locally). No secret is passed on a command line, printed, or placed in Terraform variables. Where a platform-held secret can be avoided, it is: Entra sign-in uses a federated credential of a managed identity, AWS uses web-identity federation, CI uses GitHub OIDC, and the GitHub App key is imported into Key Vault as a non-exportable key and used for signing there.

3. **Nothing is assumed configured.** `aap integrations status`, `GET /api/v1/integrations` and the Integrations page show each system as configured or not, list what is missing (names only), and give the command that sets it up. The scheduler skips unconfigured integrations. The evidence they would produce stays `no_evidence`. A connector run that cannot read something records the gap (`connector_runs`). It never reports "ok".

4. **Each connector is tested against the real service or a contract-faithful stand-in,** and the test says which:

   | Integration | Tested against |
   |---|---|
   | Dependency-Track 4.14.5 | Real container (bootstrap from first boot, OSV mirror, upload, findings) |
   | DefectDojo 3.4.0 | Real compose stack (bootstrap, SARIF reimport, dedup, scope isolation) |
   | OIDC sign-in | Real OIDC server (navikt mock-oauth2-server) plus an in-process IdP for attack cases |
   | Sigstore attestations | Real public GitHub attestation bundle, offline, both verification backends |
   | Evidence blob store | Azurite (Azure Storage emulator) |
   | AWS Security Hub / STS | moto |
   | GitHub REST, Azure Resource Graph, Logs Ingestion, Jira Cloud | Recorded API shapes (respx / contract fake). Jira has an opt-in live contract test. |

5. **The earlier prototype scaffold is reference material, not a dependency.** The platform deploys its own Dependency-Track and DefectDojo in its own Container Apps environment and database server.

## Findings that changed the design (verified on 2026-10-08)

- **GitHub artifact attestations on private repositories need GitHub Enterprise Cloud.** On other plans, evidence from private repositories is capped at C2. On Enterprise, bundles come from GitHub's own Sigstore instance (timestamp-only), which sigstore-python 4.5 cannot load. Those are verified with `gh attestation verify` offline (sigstore-go). Public-repository bundles (Sigstore public-good) are verified in-process. The certificate's runner environment and source commit now override the manifest's self-declared values.
- **DefectDojo 3.x (open source) has no role or membership API.** Access uses `authorized_users` on organizations, and the API refuses password changes. Bootstrap creates one platform organization, authorizes only the service user (no staff, no superuser, no configuration permissions), and re-asserts that on every run. DefectDojo stays an optional triage workbench (`config/integrations.yaml`).
- **Dependency-Track ≥ 4.13 shows an API key once.** Bootstrap stores it immediately. The platform team needs four permissions (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`), not portfolio management. Dependency-Track does not supply CISA KEV, so a DT sync must never clear the KEV flag set by the authoritative feed. The vulnerability upsert now preserves fields a source does not supply.
- **Jira entity properties are not JQL-searchable without a Jira app.** Idempotency uses a deterministic label `aap-k-<hash>`, with the full key kept as an issue property.

## Alternatives considered

| Option | Why not |
|---|---|
| Wait for other teams to provision access | They do not exist for this project. The platform would never leave design. |
| SaaS ASPM or managed scanners | Revisit at Phase 0 exit (ADR-001). Does not remove the need for evidence verification. |
| Static credentials everywhere (PATs, client secrets, AWS keys) | Simpler to start, but each is a long-lived secret to leak and rotate. Federation is available for every system except Jira, Dependency-Track and DefectDojo, whose tokens sit in Key Vault. |
| Drop DefectDojo | Reasonable. It is optional (`defectdojo.enabled`). It is kept for formats the platform does not parse natively. |

## Consequences

- The project team now **operates** Dependency-Track and DefectDojo: upgrades, mirrors, backups (risk R-21).
- A small number of people hold high privilege during bootstrap (tenant and subscription owner, organization owner). That is time-limited and logged (risk R-22).
- The plan of the GitHub organization (Free, Team or Enterprise) changes what is achievable: C3 on private repos and organization rulesets (decision D-018).
- Costs are the project's: Container Apps, PostgreSQL GP, GZRS storage, Sentinel ingestion.

## Security implications

- Least privilege is enforced in code, not by convention:
  - read-only GitHub App token scopes;
  - DT team permissions limited to four;
  - the DefectDojo service user scoped to one organization;
  - an AWS role trusting exactly one managed identity;
  - the worker as the only evidence writer;
  - a Sentinel publisher limited to one DCR.
- The remaining long-lived secrets are the Jira API token, the DT API key, the DefectDojo token and the PostgreSQL password. All are in Key Vault, on the rotation runbook.
- The apps still connect to PostgreSQL with the administrator login. Per-process database logins are backlog E19-F02-S03 (risk R-25).

## Operational implications

`aap integrations status` is the first thing in the operations runbook. The integration bootstrap runbook is the single ordered list of human steps. `deploy/local/bootstrap.sh` reproduces the integration world on one machine for development and tests.
