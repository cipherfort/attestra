# Access Control Model

| | |
|---|---|
| Status | IMPLEMENTED (policy module, RLS, OIDC BFF, roles from role grants and identity-provider groups or app roles). With Entra ID, `examples/terraform/azure/modules/entra` creates the groups and app-role assignments (ADR-031). |
| Decision records | [ADR-013](../../adr/ADR-013-rbac-model.md), [ADR-014](../../adr/ADR-014-authentication-architecture.md), [ADR-022](../../adr/ADR-022-multi-unit-model.md) |
| Enforcement | API policy module (primary) + PostgreSQL RLS (defence in depth, tested T5–T9) |

## 1. Principals

| Principal | Authenticates via | Notes |
|---|---|---|
| Workforce user | Your OpenID Connect identity provider (BFF); MFA and device policy enforced by the provider | Roles from role grants (to people or identity-provider groups) and app roles in the token |
| Service client | OIDC client credentials (bearer token), app roles | e.g. `Reports.Read` for BI tooling |
| Platform processes | Workload identity (managed identity / service account) | One database login per process (`aap_api_login`, `aap_worker_login`, `aap_hook_login`, `aap_reporting_login`); scoped storage/secret roles |
| GitHub (webhooks) | HMAC | Can only enqueue |
| Break-glass | A dedicated identity-provider account, monitored | An alert in your SIEM on any use |

## 2. Roles and identity-provider groups

| Platform role | Group (convention) | Scope source |
|---|---|---|
| engineer | `aap-role-engineer` (default for engineering staff) | Team membership (Admin page, or a GitHub team linked to the unit) → owning team's apps |
| champion | `aap-role-champion-<team>` | Team |
| app_owner | Derived from `application.yaml` owners (resolved identities) | Owned apps |
| unit_lead | `aap-role-unit-lead-<unit>` | The unit's subtree (any level from `config/organization.yaml`) |
| appsec_engineer | `aap-role-appsec` | Org-wide |
| governance_analyst | `aap-role-governance` | Org-wide |
| security_leadership | `aap-role-security-leadership` | Org-wide |
| executive | `aap-role-executive` | Org-wide aggregates only |
| auditor | `aap-role-auditor` (time-bound assignment) | Org-wide read |
| platform_admin | `aap-role-platform-admin` (just-in-time elevation recommended) | Platform operations, no application data |

## 3. Permission matrix (excerpt; every operation declares its permission as `x-permission` in [`schemas/api/openapi.yaml`](../../schemas/api/openapi.yaml))

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
| connector / job admin | – | – | – | – | – | – | – | – | – | ✓ |

**platform_admin has no default access to finding or evidence detail.** Investigations needing data access use an auditor/appsec assignment, which is approved and logged.

## 4. Rules

| ID | Rule |
|---|---|
| ACM-01 | Deny by default. Every API operation declares `x-permission` (validated in CI). |
| ACM-02 | Out-of-scope resources return 404 (no enumeration) |
| ACM-03 | SoD: requester ≠ approver. M2 reviewer ∉ owning team. FP marker ≠ confirmer. Override requester ≠ approver. Classification decider ≠ the person who registered the application, and not a member of the owning unit, a unit below it, or a unit above it other than the organization root (IMPLEMENTED: `services/onboarding.sod_problem`; refusals are audited). Enforced in code **and** DB constraints where expressible. |
| ACM-04 | Org-wide roles are reviewed quarterly (Admin → Role grants, plus your identity provider's access reviews). Auditor access is time-bound (≤ 90 days). |
| ACM-05 | platform_admin is assigned in the identity provider, never in the platform. Just-in-time elevation (≤ 4 h, approval, justification), for example Entra PIM, is recommended; its activation log goes to your SIEM from the identity provider. |
| ACM-06 | Database: each process connects with its own NOINHERIT login that can switch only to its own roles (the API: `aap_api` + the narrow sign-in role `aap_auth`; never `aap_worker`). The administrator login runs migrations only. Application roles have no UPDATE/DELETE on ledgers. Partitions are not directly accessible. Sessions are RLS-scoped per transaction. |
| ACM-07 | Storage: only the worker writes evidence; the API never does. Short-lived download links for raw evidence files, issued after an authorization check, are planned. |
| ACM-08 | Group membership and app roles are read from the token at sign-in, so removal from a group takes effect at the next sign-in: within 30 minutes of inactivity, and at most 8 hours (the absolute session limit). Role grants made on the Admin page take effect on the next request. |
