# ADR-019: Cloud security integration (Azure, AWS)

**Status:** Proposed (2026-10-07), amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** ADR-014 (AWS federation), controls ASC-OPS-03/05/06

## Context

Runtime posture findings (misconfiguration, exposure, runtime vulnerabilities) exist in Defender for Cloud and AWS security services. They are not attributed to applications today, so they cannot be prioritised by tier or owned by teams.

## Decision

1. **Read-only, aggregated sources, one integration per cloud:**
   - **Azure:** Azure Resource Graph (`securityresources` table: Defender for Cloud assessments and alerts metadata; `resources` for inventory) with the platform managed identity holding **Reader + Security Reader at the root management group** (or the in-scope MG). Azure Policy compliance states via Resource Graph `policyresources`.
   - **AWS:** **Security Hub** in the delegated-administrator, aggregation-region account. It already aggregates GuardDuty, Inspector, Config, IAM Access Analyzer and Firewall Manager findings. One read-only cross-account role is assumed via web identity federation (ADR-014). No direct integration with each AWS service.
2. **Attribution to applications** in precedence order:
   1. resource **tag** `aap-app-id=APP-nnnnn` (tagging standard + Azure Policy / AWS Config rule enforcing presence: PROPOSED);
   2. declared **cloud scopes** in `application.yaml` (subscription / resource group / account);
   3. unmapped → "unattributed" queue for Cloud Security. Unattributed counts are a KPI.
3. **Normalisation:** cloud findings → `findings` (type `cloud`), fingerprint `cloud|provider|resource_id|rule_id`, risk engine applies. Exposure verification uses inventory (public IPs, ingress) to cross-check `application.yaml` exposure.
4. **Not in v1:** Defender for Cloud "DevOps security" (overlaps with GHAS and our pipeline: duplicate findings), CloudTrail raw logs (SOC domain, not posture), Entra ID as a findings source (identity is consumed for RBAC, not findings), GCP (no current estate, adapter interface ready).
5. Cloud Security owns these connectors' configuration and the tagging standard.

## Alternatives considered

| Option | Why not |
|---|---|
| Per-service AWS integrations | Security Hub already aggregates. Many credentials. |
| Defender CSPM multicloud for AWS too | Possible single pane, but depends on Defender AWS connectors being in place. Revisit if Cloud Security standardises on it. |
| Push from SIEM | The SIEM holds events, not current posture state. |

## Decision drivers

Read-only · minimal credentials · use existing aggregation · attribution to apps.

## Consequences

Attribution quality depends on tagging discipline. Expect a high unattributed rate initially, and track it.

## Security implications

Reader at the root MG reveals the inventory estate-wide to the platform identity. That is acceptable for its role, and the identity is used only by the cloud connector worker. No write roles.

## Operational implications

**Created by the project** (ADR-031): role assignments by `examples/terraform/azure/modules/azure-reader` (scopes are decision D-015); AWS IAM OIDC provider + role by `examples/terraform/azure/envs/aws`. Tagging-policy rollout is a project task (E15).
