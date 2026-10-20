# ADR-025: Deployment model

**Status:** Accepted (2026-10-20), implemented; the Azure services named here are one deployment option since [ADR-032](ADR-032-open-source-product.md) made the product provider-neutral, amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** ADR-008, ADR-024, ADR-026, the earlier prototype (Container Apps precedent; reference only, ADR-031)

## Context

The organisation already runs DefectDojo and Dependency-Track on Azure Container Apps (scaffold), with Terraform (azurerm 4.x) and GitHub OIDC deployment. The new platform holds more sensitive data and must not repeat the MVP's public-ingress and broad database firewall choices (CS-2, CS-4).

## Decision

- **Azure Container Apps**, **workload-profiles environment with VNet integration** (internal environment), region **UK South**, three apps: `aap-web` (internal ingress), `aap-hook` (external ingress), `aap-worker` (no ingress, KEDA-scaled per queue).
- **Ingress:**
  - `aap-web` is reachable only from the corporate network / ZTNA through **internal** ingress plus a private DNS zone. If remote access needs it, **Front Door Premium with Private Link** to the internal environment and a WAF policy is PROPOSED.
  - `aap-hook` is the only internet-exposed component: a small dedicated app, IP restriction to GitHub `hooks` ranges (refreshed from GitHub `/meta` by a scheduled Terraform/automation job), HMAC verification, no data read access.
- **Data services:** PostgreSQL Flexible Server (zone-redundant HA, private VNet access), Blob Storage (private endpoint), Key Vault (private endpoint), ACR **Premium** (private endpoint, only signed/attested images by digest), Log Analytics + App Insights.
- **Egress:** through **NAT Gateway + Azure Firewall** created by the project (**not yet in `examples/terraform/azure`**: backlog E24-F04-S05; until then Container Apps default outbound) with an FQDN allowlist: `api.github.com`, `github.com`, `*.actions.githubusercontent.com` (artifact downloads), Jira host, FIRST/EPSS, CISA, OSV, AWS STS/Security Hub endpoints, DD/DT internal endpoints.
- **Environments:** `dev` and `prod` (separate subscriptions or RGs per landing-zone convention). Ephemeral PR environments are PROPOSED later.
- **IaC:** Terraform azurerm `~> 4.x` (matching the existing repos), remote state with Entra auth, OIDC from GitHub Actions, `plan` on PR, `apply` behind a protected environment with required reviewers.
- **Follow-up for the existing scaffold:** move DD/DT onto the same private network (private endpoints, remove `AllowAzureServices`, separate DB logins per app). Tracked as an infra-repo backlog item, not a blocker for platform Phase 1.

## Alternatives considered

| Option | Why not |
|---|---|
| AKS | More control. Significantly more operations (cluster upgrades, policies). Container Apps covers the needs, including KEDA. |
| App Service | Weaker worker/queue scaling model. Fine for web only. |
| Public ingress + IP allowlist (MVP pattern) | Insufficient for this data (CS-4). |
| AWS hosting | The organisation's existing security platform and identity are Azure-centric. |

## Decision drivers

Private by default · consistency with existing tooling · managed scaling · minimal operations.

## Consequences

Private networking makes CI deploys need private-network runners (a private-network self-hosted runner) or deployments via ARM only (control plane). Data-plane steps (migrations) run as a Container Apps **job** inside the VNet.

## Security implications

One internet-facing component with a write-only (enqueue) capability. Everything else private. Images are pulled by digest from a private ACR after attestation verification (ADR-030).

## Operational implications

The platform creates its own VNet, NSGs and private DNS zones (`examples/terraform/azure/modules/platform`, ADR-031). Peering into an organization hub, if one ever exists, is optional and not assumed.
