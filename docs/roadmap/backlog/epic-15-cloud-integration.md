# E15: Cloud Integration

**Goal:** Cloud posture findings and inventory attributed to applications. Design: [ADR-019](../../../adr/ADR-019-cloud-integration.md).

**Progress (Stage 9):** Defender (Resource Graph) and Security Hub (web identity, no keys) connectors, scope mapping, `cloud.posture` evidence, closure by re-scan IMPLEMENTED (recorded responses / moto); Terraform readers IMPLEMENTED as code.

## F01: Azure

### E15-F01-S01: Azure Resource Graph connector (Defender for Cloud, inventory, policy) · M · Phase 8
- **AC:** Managed identity with Reader + Security Reader at the in-scope scopes (`modules/azure-reader`, IMPLEMENTED as code). Assessments/alerts → `cloud` findings with fingerprint `cloud|azure|resource_id|assessment_id`. Inventory supports exposure cross-checks (public IPs, ingress) and ASC-OPS-05/06.
- **Tests:** Recorded ARG query fixtures. Pagination (`$skipToken`).

## F02: AWS

### E15-F02-S01: AWS Security Hub connector via web identity federation · S · Phase 8
- **AC:** No AWS keys. `AssumeRoleWithWebIdentity` with an Entra token (IAM OIDC provider + role: `examples/terraform/azure/envs/aws`, IMPLEMENTED as code). Findings from the aggregation region (GuardDuty, Inspector, Config, Access Analyzer included via Security Hub) → `cloud` findings.
- **Security:** Read-only role (`SecurityAudit`-style subset). Session duration ≤ 1h.

## F03: Attribution

### E15-F03-S01: App attribution by tag and declared scope · M · Phase 8
- **AC:** Precedence: `aap-app-id` tag → declared cloud scopes → unattributed queue. Unattributed % KPI. A tagging-standard document and an Azure Policy / AWS Config rule proposal handed to Cloud Security.

### E15-F03-S02: Exposure verification · S · Phase 8
- **AC:** If inventory shows internet exposure contrary to `application.yaml`, raise a finding and use the more exposed value for classification and risk (reported to the owner).
