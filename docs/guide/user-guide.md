# User guide

What each person does with the platform, in the order they usually meet it. What you can see is limited to the
applications of the units you belong to; anything else looks as if it did not exist.

## Everyone: reading an application

- **Tier** (1 critical … 4 low) comes from the application's own classification answers; "Why Tier N?" shows the
  points and the rules that set a minimum.
- **Mandatory controls proven** counts controls satisfied by *current* evidence. States: satisfied, partial, not
  satisfied, stale (evidence too old or from an older commit), no evidence, excepted, not applicable, not evaluated.
- Every state links to its **evidence**: who produced it (an approved pipeline at a commit, a connector, a person),
  its confidence (C0–C3 automated, M1–M2 manual), when it was observed, and the hash chain entry that makes it
  tamper-evident.
- **Findings** carry a contextual priority (P1–P4) and a deadline (P1 7 days … P4 180 days).

## Security champions and engineers

| Task | Where |
|---|---|
| Register your application | Applications → **Register an application**: read `.security/application.yaml` from the repository (GitHub or GitLab), or paste it. Tier 1/2 waits for AppSec; Tier 3/4 is approved automatically |
| Get scan evidence | Add the caller workflow (GitHub) or the component include (GitLab) your AppSec team publishes ([pipelines](../../pipelines/README.md)). Evidence appears after the next run on the default branch |
| Triage a finding | Finding → **Triage**; or **Request false positive** with a justification (an AppSec engineer confirms; never the requester) |
| Accept a risk for now | Application → **Request exception** on a control or finding: justification, risk, residual priority, remediation plan. Submit it; Tier 1/2 also needs the business owner's co-signature |
| Record a manual check | Application → **Start an assessment** (manual control, threat model review, architecture review, pen test, SAMM interview). You record and submit; someone else reviews |

## AppSec engineers

| Task | Where |
|---|---|
| Approve classifications | Application → Classification: **Approve Tier N** (only if you did not request it and are outside the owning team) |
| Decide exceptions | Exceptions → an item waiting for a decision: approve with an expiry within the policy maximum, or reject. The required approver role is shown |
| Review assessments | Assessments → submitted ones: approving outside the owning team makes the evidence M2 (independent), inside it M1 |
| Confirm false positives | Finding → **Confirm false positive** |
| Answer "are we affected?" | Are we affected? → a CVE or GHSA id |

## Unit leads and leadership

- **Leadership** page: the scorecard for your scope, maturity against targets, and **Export** (CSV of open findings or
  control states, audited) or **Print / save as PDF**.
- Unit leads approve exceptions their role allows at their applications' tier (see the policy shown on each exception).

## Platform administrators

**Admin**: the organization tree (levels from `config/organization.yaml`), members of each unit, and role grants
(scoped roles need a unit). You cannot change your own roles; platform administrators are assigned in the identity
provider. Every change is audited. **Integrations** shows each plugin: configured or not, what is missing, last run.

## What the platform will not do

- Mark a control satisfied because a setting says a scan *should* run.
- Close a finding because a ticket was closed.
- Let anyone approve their own request, or a request from their own team where independence is required.
- Show you an application outside your scope (you get "not found", by design).
