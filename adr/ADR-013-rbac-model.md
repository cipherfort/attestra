# ADR-013: RBAC model

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-014, ADR-022, [Platform security section 3.1](../docs/security/platform-security-architecture.md#31-identity-and-access)

## Context

Users range from engineers (their team's apps) to executives (aggregates) to auditors (read-only evidence). Data is sensitive. Several actions need segregation of duties.

## Decision

**Role-based access control with scopes**, enforced in a single policy module in the API and backed by PostgreSQL RLS.

| Role | Scope | Can | Cannot |
|---|---|---|---|
| `engineer` | Own team's apps (derived from GitHub team ↔ Entra group) | View app, findings, controls, evidence. Triage P3/P4. Request exceptions. | Approve anything. See other teams' apps. |
| `champion` | Own team's apps | + triage all priorities, mark false positive (P1/P2 needs a second reviewer), record M1 evidence | Approve own team's exceptions or M2 evidence |
| `app_owner` | Owned apps | + co-sign Tier 1/2 exceptions, approve classification inputs | |
| `unit_lead` | Directorate subtree | View all directorate apps. Approve exceptions per threshold table. | Approve where they are the requester |
| `appsec_engineer` | Org-wide read | Record M2 evidence (not for own apps), confirm FPs, approve exceptions per threshold, approve tier changes | Change catalogue/config at runtime (PR only) |
| `governance_analyst` | Org-wide read | Manage exception workflow admin, reporting packs | Approve exceptions |
| `security_leadership` | Org-wide | All read, approve per threshold (CISO: P1) | |
| `executive` | Org-wide **aggregates only** | Exec dashboards | Finding-level detail |
| `auditor` | Org-wide read (time-bound assignment) | Evidence chains, control history, audit log | Any write |
| `platform_admin` | Platform operations | Connector config, job replay, user/role sync | **Read finding detail by default**, write ledgers. Elevation via PIM (4h, approval). |

Rules:
- **Deny by default.** Every endpoint declares its permission. CI fails for an endpoint without a policy annotation.
- **Out-of-scope resources return 404**, not 403 (no enumeration).
- **SoD constraints** are evaluated in the policy module (requester ≠ approver; reviewer ∉ owning team; FP marker ≠ confirmer).
- Roles come from **Entra groups** (`aap-role-<role>[-<scope>]`). Team scope comes from GitHub team ↔ Entra group sync, refreshed hourly.
- RLS gets the caller's expanded org-unit set per transaction (tested: T5–T7).

## Alternatives considered

| Option | Why not |
|---|---|
| ABAC with OPA/Rego or Cedar | More expressive. Not needed for v1's rules. Policy-as-code engines add a dependency. **The policy module is written so it can be swapped for Cedar** if rules grow. |
| Entra app roles only | Cannot express per-application scope or SoD. |
| Per-directorate deployments | Breaks org-wide views (ADR-022). |

## Decision drivers

Least privilege · SoD enforcement · simplicity · testability.

## Consequences

A large authorisation test matrix (role × endpoint × scope) runs in CI. Group-sync lag of up to 1h for new joiners is accepted.

## Security implications

Directly addresses threats T-06 and T-07. Platform admins deliberately lack default access to finding detail.

## Operational implications

Entra groups and app-role assignments are created by `examples/terraform/azure/modules/entra` (ADR-031); membership is managed by the project's Groups Administrator. Quarterly access review of org-wide roles.
