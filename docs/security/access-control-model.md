# Access Control Model

| | |
|---|---|
| Status | IMPLEMENTED (policy module, RLS, Entra OIDC BFF, app roles from groups). Groups and app-role assignments are created by `examples/terraform/azure/modules/entra` (ADR-031). |
| Decision records | [ADR-013](../../adr/ADR-013-rbac-model.md), [ADR-014](../../adr/ADR-014-authentication-architecture.md), [ADR-022](../../adr/ADR-022-multi-unit-model.md) |
| Enforcement | API policy module (primary) + PostgreSQL RLS (defence in depth, tested T5–T9) |

## 1. Principals

| Principal | Authenticates via | Notes |
|---|---|---|
| Workforce user | Entra ID OIDC (BFF), Conditional Access (MFA, compliant device) | Roles from Entra groups |
| Service client | Entra client credentials, app roles | e.g. `Reports.Read` for BI tooling |
| Platform processes | Workload identity (managed identity / service account) | One database login per process (`aap_api_login`, `aap_worker_login`, `aap_hook_login`, `aap_reporting_login`); scoped storage/secret roles |
| GitHub (webhooks) | HMAC | Can only enqueue |
| Break-glass | Dedicated Entra account, monitored | Sentinel alert on any use |

## 2. Roles and Entra groups

| Platform role | Entra group (convention) | Scope source |
|---|---|---|
| engineer | `aap-role-engineer` (default for engineering staff) | GitHub team ↔ Entra group membership → owning team's apps |
| champion | `aap-role-champion-<team>` | Team |
| app_owner | Derived from `application.yaml` owners (resolved identities) | Owned apps |
| unit_lead | `aap-role-unit-lead-<unit>` | The unit's subtree (any level from `config/organization.yaml`) |
| appsec_engineer | `aap-role-appsec` | Org-wide |
| governance_analyst | `aap-role-governance` | Org-wide |
| security_leadership | `aap-role-security-leadership` | Org-wide |
| executive | `aap-role-executive` | Org-wide aggregates only |
| auditor | `aap-role-auditor` (time-bound assignment via access package) | Org-wide read |
| platform_admin | `aap-role-platform-admin` (**PIM eligible only**) | Platform operations |

## 3. Permission matrix (excerpt; full matrix generated from OpenAPI `x-permission` in E19)

| Permission (`x-permission`) | engineer | champion | app_owner | unit_lead | appsec_engineer | governance_analyst | security_leadership | executive | auditor | platform_admin |
|---|---|---|---|---|---|---|---|---|---|---|
| application.read | team | team | owned | unit subtree | org | org | org | – | org | – |
| application.settings.write | – | team | owned | unit subtree | – | – | – | – | – | – |
| application.register | – | team | – | unit subtree | org | – | – | – | – | – |
| evidence.read | team | team | owned | unit subtree | org | org | org | – | org | – |
| evidence.raw.read | – | team | – | – | org | – | org | – | org | – |
| finding.read | team | team | owned | unit subtree | org | org | org | – | org | – |
| finding.transition (triage P3/P4) | team | team | – | – | org | – | – | – | – | – |
| finding.fp.confirm (P1/P2) | – | – | – | – | org (≠ marker) | – | – | – | – | – |
| finding.priority.override (approve) | – | – | – | – | org (≠ requester) | – | – | – | – | – |
| exception.request | team | team | owned | – | – | – | – | – | – | – |
| exception.decide | – | – | co-sign T1/2 | per threshold | per threshold | – | per threshold | – | – | – |
| classification.decide | – | – | – | – | org (≠ requester, ∉ owning unit chain) | – | org | – | – | – |
| assessment.create / assessment.answer | – | team | – | unit subtree | org | – | – | – | – | – |
| assessment.approve | – | – | – | – | org (≠ lead assessor; M2 only if outside the owning unit chain, else M1) | org (org-scope) | org | – | – | – |
| vulnerability.impact.read | team scope | team scope | owned | unit subtree | org | org | org | – | org | – |
| vulnerability.impact.export | – | – | – | unit subtree | org | org | org | – | org | – |
| maturity.rollup.read | – | – | – | unit subtree | org | org | org | org | org | – |
| report.org.read | – | – | – | – | org | org | org | org | org | – |
| report.export | – | – | – | unit subtree | org | org | org | – | org | – |
| org.admin (units, membership, role grants; runs as `aap_admin`) | – | – | – | – | – | – | – | – | – | org (never self; never platform_admin) |
| catalogue.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| connector / job admin | – | – | – | – | – | – | – | – | – | ✓ (PIM) |

**platform_admin has no default access to finding or evidence detail.** Investigations needing data access use an auditor/appsec assignment, which is approved and logged.

## 4. Rules

| ID | Rule |
|---|---|
| ACM-01 | Deny by default. Every API operation declares `x-permission` (validated in CI). |
| ACM-02 | Out-of-scope resources return 404 (no enumeration) |
| ACM-03 | SoD: requester ≠ approver. M2 reviewer ∉ owning team. FP marker ≠ confirmer. Override requester ≠ approver. Classification decider ≠ the person who registered the application, and not a member of the owning unit, a unit below it, or a unit above it other than the organization root (IMPLEMENTED: `services/onboarding.sod_problem`; refusals are audited). Enforced in code **and** DB constraints where expressible. |
| ACM-04 | Org-wide roles are reviewed quarterly (Entra access reviews). Auditor access is time-bound (≤ 90 days). |
| ACM-05 | platform_admin only via PIM (≤ 4h, approval, justification). Activation emits a SIEM event. |
| ACM-06 | Database: each process connects with its own NOINHERIT login that can switch only to its own roles (the API: `aap_api` + the narrow sign-in role `aap_auth`; never `aap_worker`). The administrator login runs migrations only. Application roles have no UPDATE/DELETE on ledgers. Partitions are not directly accessible. Sessions are RLS-scoped per transaction. |
| ACM-07 | Storage: only the ingestion identity writes evidence. The API identity issues single-blob, ≤ 5-minute read SAS after an authZ check. |
| ACM-08 | Group-sync lag ≤ 1h. Removal from an Entra group revokes the role at next sync. Sessions are re-evaluated every 30 minutes (idle timeout). |
