# ADR-021: Security exception management

**Status:** Accepted (2026-10-20), implemented  ·  **Related:** [Governance section 4](../adoption-kit/governance/governance-model.md#4-risk-acceptance-exception-approval-thresholds), schema tests T2–T3

## Context

Not every control or finding can be met on time. Today "risk accepted" is a tool status with no owner, approver or expiry (CS-6). Unmanaged exceptions become permanent invisible risk.

## Decision

1. **Exceptions exist only in the platform.** They are not in repo files (anyone with write access could self-grant) and not as tool suppressions.
2. **Targets:** `control` (a gap for an app/scope), `finding`, `requirement` (ASVS), `sla` (extension).
3. **Required fields:** app, target, justification, risk description, residual priority, compensating controls, remediation plan with date, owner, requester, approver, created/approved/start/expiry/review dates. Enforced in schema (approved ⇒ approver + expiry; approver ≠ requester).
4. **Approver** by residual priority × tier (governance table). Tier 1/2 business-owner co-sign. SoD enforced in code and schema.
5. **Max duration** per control (catalogue) and per priority. Renewals need fresh approval. More than 2 renewals escalate a level.
6. **Expiry:** a scheduler job flips status → `expired`, creates an `exception_expired` finding with a half-length SLA, re-opens the original finding/control gap, and notifies the owner, approver and business unit lead.
7. **Compensating controls** reduce impact by at most one level in the risk model, and only when recorded and approved (ADR-011).
8. **Tool-level suppressions are tracked, not trusted.** DefectDojo "risk accepted", GHAS "won't fix" and Checkov `skip` comments are ingested as *suppressions*. A suppression without a matching platform exception shows as "unmanaged suppression" and does **not** change the finding's platform status. Unmanaged suppressions are a team metric.
9. **Not applicable ≠ exception.** N/A (control doesn't apply) has its own lighter approval and is reviewed at classification review.
10. **No-exception controls** are listed in the catalogue (e.g. active secrets, malicious packages).

## Alternatives considered

| Option | Why not |
|---|---|
| `.security/exceptions.yaml` in repo (brief's sketch) | Self-approval risk. No SoD. |
| GRC tool for exceptions | Possible integration later. The link to findings/controls/evidence must remain in the platform, otherwise expiry cannot reopen findings automatically. |
| Tool-native acceptance | Ungoverned (CS-6). |

## Decision drivers

Governed risk acceptance · automatic expiry · SoD · visibility.

## Consequences

Teams must request exceptions in the platform even when a tool suppression is quicker. Unmanaged-suppression reporting creates that incentive.

## Security implications

Exceptions are a prime abuse path (threat T-07). Covered by SoD, audit events and Sentinel events for P1 approvals.

## Operational implications

GOV operates the workflow queue. Weekly expiring-soon digest.
