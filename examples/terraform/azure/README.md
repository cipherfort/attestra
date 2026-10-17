# Reference Terraform: Azure (EXAMPLE)

A complete Azure deployment (Container Apps, PostgreSQL, Blob with WORM, Key Vault, Entra ID, Sentinel) plus the AWS
Security Hub reader role and the GitHub organization settings. Copy and adapt it; the supported, cloud-neutral path is
the [Helm chart](../../../charts/attestra/README.md).

Everything the platform runs on, and every external system it integrates with, created from nothing ([ADR-031](../../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md)). Step-by-step order and human actions: [integration bootstrap runbook](../../../docs/operations/integration-bootstrap.md).

**Status: IMPLEMENTED, validated, not applied.**
- `terraform validate` passes for every root against the real provider schemas: azurerm 4.81, azuread 3.10, azapi 2.13, aws 6.68, github 6.13.
- Checkov reports 78 passed, 0 failed and 22 skipped, each skip with a written reason in the code.
- Nothing has been applied to a real tenant. Expect first-apply fixes: plan-time checks need credentials, so they have not run.

## Roots: one per privileged human

| Root | Applied by (project role) | Creates |
|---|---|---|
| `state-bootstrap` | Subscription Owner, once, local state | State storage: Entra-only, versioned, delete lock |
| `envs/azure` | Subscription Owner + Entra Application/Groups Administrator | Modules `platform`, `entra`, `sentinel`, `scanners`, `azure-reader` |
| `envs/aws` | AWS administrator of the Security Hub aggregation account | Module `aws-reader` (IAM OIDC provider for Entra + one read-only role) |
| `envs/github` | GitHub organization owner | Module `github-org` (security-workflows repo, rulesets, team, Actions policy) |

## Modules

| Module | Contents | Notable choices |
|---|---|---|
| `platform` | VNet with NSGs; private DNS; three managed identities (api, worker, hook); Key Vault (premium, RBAC, private); PostgreSQL 16 (VNet-injected, geo-backup, optional zone HA); evidence storage (GZRS, no shared keys, private, **version-level WORM**, read/write/delete logs); ACR; Container Apps environment; api/hook/worker apps; migrate job; GitHub-OIDC deploy identity | Only the worker writes evidence; the api reads. The GitHub App key is a non-exportable HSM key (Key Vault Crypto User for the worker). The WORM policy stays `Unlocked` until decision D-016. |
| `entra` | `aap-web` (BFF client), `aap-api` (service clients, `Reports.Read`), app roles, `aap-role-*` groups, scoped groups, **federated credential** of the API's managed identity | No client secret exists. `ApplicationGroup` claims (no group overage). Assignment required. |
| `sentinel` | Sentinel onboarding, `AppSecPlatform_CL` (columns from `columns.auto.json`, generated from the code and tested), DCE/DCR, publisher and reader roles, analytics rules including "checkpoint missing" | The publisher can write to one DCR and nothing else |
| `scanners` | Dependency-Track 4.14.5, DefectDojo 3.4.0 (valkey, uwsgi, celery, nginx, init job), databases on the platform server, secrets in Key Vault, **bootstrap jobs** inside the VNet | Internal ingress unless `ui_allowed_cidrs` is set. Same versions as `deploy/local` |
| `azure-reader` | Reader + Security Reader for the worker at chosen scopes | Scopes are decision D-015 |
| `aws-reader` | IAM OIDC provider (Entra v2 issuer), role trusting exactly one managed identity, `AWSSecurityHubReadOnlyAccess` | No AWS keys |
| `github-org` | `security-workflows` repo + rulesets + immutable release tags, `appsec-platform` team, Actions allowlist, org access to private reusable workflows, optional org ruleset (evaluate mode) | The GitHub App itself cannot be created by Terraform: `aap bootstrap github-app` |

## Known gaps (tracked)

- The apps connect to PostgreSQL with the administrator login. Per-process database logins mapped to `aap_api`/`aap_worker`/`aap_hook` are backlog E19-F02-S03 (risk R-25).
- Dependency-Track `/data` is ephemeral (indexes rebuild on restart).
- No controlled egress yet (ADR-025 NAT Gateway + Azure Firewall allowlist): backlog E24-F04-S05, before production use.
- ACR is Standard: Premium with a private endpoint is proposed.
- The Logs Ingestion endpoint is public (Entra-authenticated): AMPLS is a later hardening step.
- azurerm 5.x exists. The upgrade is backlog, deliberately not mixed with first deployment.

## Validate locally (what CI runs)

```bash
terraform fmt -check -recursive examples/terraform/azure
for r in state-bootstrap envs/azure envs/aws envs/github; do
  terraform -chdir=examples/terraform/azure/$r init -backend=false && terraform -chdir=examples/terraform/azure/$r validate; done
checkov -d examples/terraform/azure --framework terraform --quiet --compact --skip-path '\.terraform'
```
