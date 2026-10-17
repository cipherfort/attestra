# Security Exception Standard

| | |
|---|---|
| ID | STD-10 · Status: DRAFT, REQUIRES HUMAN APPROVAL (CISO) |
| Owner | Head of Application Security. Operated by Security Governance. |
| Configuration | [`config/exception-policy.yaml`](../../config/exception-policy.yaml) |
| Related | [ADR-021](../../adr/ADR-021-security-exceptions.md), [Governance model §4](../../adoption-kit/governance/governance-model.md#4-risk-acceptance-exception-approval-thresholds) |

## 1. Purpose

Provides a governed, time-bound way to accept risk when a control, requirement or remediation SLA cannot be met.

## 2. Principles

1. An exception is a **risk decision by an accountable person**, not a technical setting.
2. Exceptions exist **only in the platform**. Repo files and scanner suppressions are never risk acceptance.
3. Every exception **expires**. Expiry is enforced automatically.
4. The approver is **independent** of the requester and the owning team.

## 3. What can be excepted

| Target | Example |
|---|---|
| `control` | ASC-TST-01 DAST cannot run until the test environment exists |
| `finding` | Vulnerable library with no fixed version, mitigated by WAF rule |
| `requirement` | ASVS V11 cryptography requirement unmet by a legacy component |
| `sla` | Remediation needs a vendor release due after the SLA date |

**Not exceptable:** application registration and classification, active exposed secrets, malicious packages, exception governance itself (ASC-VUL-03), and any control marked `exception: { allowed: false }` in the catalogue.

## 4. Required content

Application · target · justification · risk description · residual priority · compensating controls (if any) · remediation plan with date · owner · requester · expiry date. All fields are mandatory except compensating controls.

## 5. Approval

| Residual priority | Tier 1 | Tier 2 | Tier 3 | Tier 4 | Max duration |
|---|---|---|---|---|---|
| P1 | CISO | CISO | Head of AppSec | Head of AppSec | 30 days, 1 renewal |
| P2 | Head of AppSec | Head of AppSec | Directorate Security Lead | Directorate Security Lead | 90 days |
| P3 | Head of AppSec | Directorate Security Lead | Directorate Security Lead | AppSec engineer | 180 days |
| P4 | Directorate Security Lead | AppSec engineer | AppSec engineer | AppSec engineer | 365 days |

- A more senior approver may always approve.
- **Tier 1/2: the business owner co-signs.**
- The shorter of the policy maximum and the control's `exception.max_days` applies.
- **SoD:** approver ≠ requester, technical owner, or owning-team member. Self-approval attempts are blocked and reported to the SOC.

## 6. Lifecycle

`draft → pending_approval → approved | rejected` · `approved → expired | revoked | closed (remediated)` · renewal creates a new exception linked to the previous one (fresh approval; more than 2 renewals escalate a level).

On **expiry**: an `exception_expired` finding is created with half the normal SLA, the original finding or control gap reopens, and the owner, approver and Directorate Security Lead are notified. Reminders go out at 30, 14 and 3 days before expiry.

## 7. Compensating controls

May reduce the risk-model impact by at most one level, and only when described, approved and (where possible) evidenced.

## 8. Reporting

Exception health (VUL-06), expired-not-remediated (KRI-03) and unmanaged suppressions (KRI-07) are reported monthly to the Governance Board.
