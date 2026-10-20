# Cloud Security Integration Guide

| | |
|---|---|
| Audience | Cloud Security, platform engineers, application teams |
| Status | IMPLEMENTED: Defender for Cloud (Azure Resource Graph) and AWS Security Hub connectors, tested against recorded responses and moto. The setup steps below happen in your cloud accounts. |
| Limitation | The AWS connector signs in to AWS with the platform's Azure identity (`AssumeRoleWithWebIdentity` with an Entra token), so the platform must run on Azure or have Azure workload identity. Running on AWS with its own identity (IRSA) is planned. |
| Decision | [ADR-019](../../adr/ADR-019-cloud-integration.md), [ADR-014](../../adr/ADR-014-authentication-architecture.md) (federation) |

## 1. What the integration does

Pulls **read-only** posture findings and inventory from Azure (Defender for Cloud via Azure Resource Graph) and AWS (Security Hub aggregator), attributes them to applications, and puts them through the same risk, SLA and ticket flow as other findings (ASC-OPS-03). Inventory is also used to verify declared exposure and data stores (ASC-OPS-05) and decommissioning (ASC-OPS-06).

## 2. Azure setup (Cloud Security + IAM)

| Step | Detail |
|---|---|
| 1 | Use the platform worker's user-assigned managed identity (created by platform Terraform) |
| 2 | Assign **Reader** and **Security Reader** at the in-scope management group (or root MG) |
| 3 | Confirm Defender for Cloud plans are enabled on in-scope subscriptions (CSPM at minimum) |
| 4 | Allow egress from the platform to `management.azure.com` |
| 5 | Agree the tagging standard: `aap-app-id=APP-nnnnn` on resource groups (and resources where RGs are shared). Azure Policy: audit (later deny) RGs missing the tag in landing-zone subscriptions. |

Queries used (illustrative KQL for Resource Graph):
```kusto
securityresources
| where type == "microsoft.security/assessments"
| extend status = tostring(properties.status.code), severity = tostring(properties.metadata.severity)
| where status == "Unhealthy"
| project id, resourceId = tostring(properties.resourceDetails.Id), name = tostring(properties.displayName), severity
```

## 3. AWS setup (Cloud Security)

| Step | Detail |
|---|---|
| 1 | Security Hub enabled with a **delegated administrator** account and cross-region aggregation |
| 2 | In the admin account, create an **IAM OIDC identity provider** for the platform's Entra tenant (issuer `https://sts.windows.net/<tenant-id>/` or the v2 endpoint; check which one your tenant issues) with audience = the platform's app registration |
| 3 | Create role `aap-securityhub-reader` trusting that provider, with conditions on `aud` and `sub` (= the managed identity's object ID). Permissions: `securityhub:GetFindings`, `securityhub:DescribeHub`, `securityhub:ListFindingAggregators`, plus read-only `tag:GetResources` and `organizations:DescribeAccount`. Max session 1h. |
| 4 | Tagging standard `aap-app-id` on workloads; an AWS Config `required-tags` rule enforces it (recommended). |

The platform exchanges its Entra token via `AssumeRoleWithWebIdentity`. **No AWS access keys exist anywhere.**

## 4. Attribution rules

1. Resource tag `aap-app-id` → application.
2. Else, a cloud scope declared in `application.yaml` (subscription / resource group / account) contains the resource.
3. Else → **unattributed** queue owned by Cloud Security (KRI-06).

Conflicts (tag says APP-1, scope says APP-2): the tag wins and a data-quality item is raised.

## 5. What application teams do

Declare cloud scopes under `environments[].cloud` in `application.yaml` · tag resources with `aap-app-id` · remediate attributed findings within SLA or raise an exception.

## 6. Out of scope (v1)

Defender for Cloud DevOps security (duplicates GHAS findings) · raw CloudTrail/activity logs (SOC domain) · GCP (adapter-ready, no estate).
