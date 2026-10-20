# Reference deployment on Azure

One complete, worked deployment: Azure Container Apps, Entra ID, Key Vault and Sentinel, with GitHub, Jira and the
scanners, built from [examples/terraform/azure](../../examples/terraform/azure/README.md). On any other Kubernetes, use
[Helm](../install/helm.md) and [Connect your organization](../guide/connect-your-organization.md) instead.

| | |
|---|---|
| Status | IMPLEMENTED as code and commands (Terraform validated, bootstrap commands tested against real services locally). The shipped GitHub workflows run on a real GitHub organization; the cloud and Azure tenant steps have not been applied to a real tenant yet. |
| Decision | [ADR-031](../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md): the project creates and owns every integration. Nothing is assumed to exist. |
| Audience | The platform team member running each step. The "Who" column names a role on this project ([RACI](../../adoption-kit/programme/raci/raci.md)), not another team. |
| Check progress | `aap integrations status`, or the **Integrations** page (platform admin, AppSec, security leadership) |

The order matters: each step consumes the outputs of the previous one. Expect about a day of elapsed time, mostly waiting for approvals.

## 0. Accounts the project creates (human, once)

These are the only things that cannot be created as code. The project sponsor approves them, and the platform lead creates them.

| Account | Why | Notes |
|---|---|---|
| Entra tenant + Azure subscription | Hosts the platform, identities, Sentinel | Use the organization's tenant if one exists and the project is given its own subscription. Otherwise a new tenant. |
| GitHub organization | Source of truth for repositories and evidence | **Plan matters**: Enterprise Cloud is needed for attestations on private repositories (otherwise C2 at most) and for organization rulesets. |
| Jira Cloud site (or an existing site with a project the platform owns) | Remediation tickets | A service account (a licensed user) owns the API token. |
| AWS account for Security Hub aggregation (only if AWS is in scope) | Cloud posture | Delegated administrator for Security Hub in the AWS organization. |

## 1. Terraform state (Azure subscription Owner)

```bash
cd examples/terraform/azure/state-bootstrap
az login && terraform init && terraform apply -var name=aap -var location=<azure-region>
terraform output -raw backend_config > ../envs/azure/dev.backend.hcl   # not a secret
```

Verify: the storage account has shared keys disabled and a `CanNotDelete` lock.

## 2. Azure platform, Entra, Sentinel, scanners (Subscription Owner + Entra Application Administrator + Groups Administrator)

```bash
cd examples/terraform/azure/envs/azure
cp terraform.tfvars.example dev.tfvars      # fill subscription_id, name, secret_officer_object_ids, defender_scopes
terraform init -backend-config=dev.backend.hcl -backend-config="key=azure-dev.tfstate"
terraform apply -var-file=dev.tfvars        # first apply: image = "" (placeholder container)
terraform output                            # public_url, webhook_url, registry, role_groups, deploy, ...
```

This creates everything in [ADR-031 section 1](../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md#decision) except the GitHub, AWS and Jira items. Verify:
- Key Vault, PostgreSQL and evidence storage have no public network access (the Key Vault is open only to `operator_ip_ranges`).
- The evidence storage account shows a version-level immutability policy in state **Unlocked**.
- The `aap-role-*` groups exist and are assigned to the `FortProof (web)` enterprise application, with "assignment required" on.

## 3. Image and database (platform engineer)

Container Apps pull from the registry Terraform created. Build your image there: the platform with your rules, from
your fork of this repository (as below), or a two-line Dockerfile on top of a release
([your rules](../guide/connect-your-organization.md#2-your-rules)):

```bash
az acr build -r <registry> -t aap:$(git rev-parse --short HEAD) .
terraform apply -var-file=dev.tfvars -var image=<registry>/aap:<sha>
az containerapp job start -g <rg> -n job-<name>-migrate         # migrations + config load
az containerapp job start -g <rg> -n job-<name>-dd-init         # DefectDojo schema + admin
```

Later releases use the example workflow [`examples/github-actions/deploy-azure-container-apps.yml`](../../examples/github-actions/deploy-azure-container-apps.yml) (copy it into your deployment repository): GitHub OIDC to the deploy identity (`github_deploy_subjects`), image scan, provenance attestation, migration, rollout. Set the GitHub environment **variables** from `terraform output deploy`. There are no secrets to set.

## 4. Dependency-Track and DefectDojo credentials (platform engineer)

```bash
az containerapp job start -g <rg> -n job-<name>-boot-dtrack   # admin password rotated, team key → Key Vault
az containerapp job start -g <rg> -n job-<name>-boot-dd       # service user scoped to one organization → Key Vault
```

Then add an NVD API key to Dependency-Track (free; request it at nvd.nist.gov/developers). OSV mirroring is already enabled. Verify: `aap integrations status` shows both as configured, and `aap integrations run dependency_track` ends `ok`.

## 5. Sign-in (people with Entra Groups Administrator)

1. Add people to the `aap-role-*` groups: `aap-role-appsec-engineer`, `aap-role-security-leadership`, and so on. Make `platform_admin` PIM-eligible only.
2. Scoped roles (champion, business unit lead): grant them to people on the **Admin** page, or to an Entra group through the API (`POST /api/v1/admin/role-assignments` with `principal_type: idp_group`). A unit can also take its members from an Entra group (`idp_group_id`).

Verify: sign in at `public_url`. `/api/v1/users/me` lists the expected roles. A user in no group is refused by Entra ("assignment required").

## 6. GitHub organization baseline (GitHub organization owner)

```bash
cd examples/terraform/azure/envs/github
GITHUB_TOKEN=$(gh auth token) terraform apply -var org=<org> -var 'appsec_maintainers=["<login>"]' \
  -var org_rulesets_available=<true on Team/Enterprise>
```

Creates `security-workflows` with protection, immutable release tags, the `appsec-platform` team, and an allowlist-only Actions policy. Set `workflow_repository` in `config/trusted-producers.yaml` to the output (by PR). `aap pipelines approve` adds each released commit of the workflows ([shipped pipelines](../../pipelines/README.md)).

## 7. GitHub App (GitHub organization owner, at a workstation)

The workstation needs Key Vault access (`operator_ip_ranges`) and the Secrets Officer role.

```bash
export AAP_SECRETS_BACKEND=keyvault AAP_KEYVAULT_URL=<key_vault_uri>
uv run aap bootstrap github-app --org <org> --public-url https://<hook fqdn>   # browser opens: click "Create GitHub App"
uv run aap bootstrap github-app-key-to-keyvault                                 # key becomes non-exportable; secret deleted
```

1. Open the printed `install_url` and install the App on the application repositories, or on all repositories.
2. Put `github_org`, `github_app_client_id` and `github_app_key_id` (both printed) in `dev.tfvars`, then `terraform apply`.

Verify: `aap integrations run github` ends `ok` or `partial`. Partial lists repositories or settings the App cannot read. That is a permission gap to fix, never treated as a pass.

## 8. Cloud posture

- **Azure:** `defender_scopes` in step 2 already granted Reader + Security Reader. Which scopes to cover is your decision (below).
- **AWS (AWS administrator of the aggregation account):**

  ```bash
  cd examples/terraform/azure/envs/aws
  terraform apply -var tenant_id=<tenant> -var worker_principal_id=<terraform output worker_identity.principal_id>
  ```

  Put `aws_role_arn` and `aws_accounts` in `dev.tfvars` and re-apply step 2. Verify on the first run: `aap integrations run aws`. If STS refuses the token, the run records the error. Compare the token's `iss`/`aud`/`sub` with the trust policy (module `aws-reader`).

Map each application's cloud scopes in its `application.yaml` (`environments[].cloud`). Findings in unmapped scopes are counted as `unmapped_findings` in the run, never dropped.

## 9. Jira (Jira site admin creates the token; platform engineer runs the command)

```bash
export AAP_SECRETS_BACKEND=keyvault AAP_KEYVAULT_URL=<key_vault_uri>
read -rs JIRA_TOKEN && export JIRA_TOKEN       # token of the service account; never on the command line
uv run aap bootstrap jira --url https://<site>.atlassian.net --email <service account> --token-env JIRA_TOKEN --create-project SEC
```

Then:
1. Set `jira.default_project` (or `default_project_by_org_unit`) in `config/integrations.yaml` by PR.
2. Put `jira_url` and `jira_email` in tfvars and re-apply.
3. Optionally restrict visibility with a Jira issue security scheme (ADR-018).

Verify: `aap integrations run jira`. Optionally run the live contract test (`AAP_TEST_JIRA_*`, see `backend/tests/integration/test_ticketing.py`).

## 10. Sentinel (SOC lead approves; nothing to apply)

Step 2 already created the workspace onboarding, the `AppSecPlatform_CL` table, the DCE/DCR and the analytics rules.
- Agree the event list in `config/siem-events.yaml` with your security operations team before switching the export on.

Verify: within 24 hours a `checkpoint.daily` row arrives. The rule "no evidence checkpoint received in 26 hours" stays quiet.

## 11. Decisions still needed (none blocks the steps above)

| Decision | Default until decided |
|---|---|
| Defender / AWS coverage scopes | Only the scopes listed in tfvars |
| Lock the evidence WORM policy (irreversible) | `Unlocked` (evaluation) |
| Jira projects per business unit | One `SEC` project |
| GitHub plan (Enterprise Cloud for private-repo attestations and org rulesets) | Repository rulesets; private-repo evidence capped at C2 |
| Records-management approval of retention (ADR-017) | 7-year WORM period, unlocked |

## 12. Local equivalent (developers, CI)

`deploy/local/bootstrap.sh scanners` runs steps 2–5 on one machine:
- PostgreSQL;
- an OIDC provider standing in for Entra;
- Azurite standing in for Blob storage;
- Dependency-Track 4.14.5 and DefectDojo 3.4.0, bootstrapped with the same commands.

See [`deploy/local/README.md`](../../deploy/local/README.md).
