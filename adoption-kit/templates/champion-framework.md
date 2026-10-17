# Security champions — {{ORGANIZATION}}

## The role

One champion per team (or per application for Tier 1). {{TIME_ALLOCATION, e.g. 10 % of their time}}, recognized in
objectives. Champions are engineers in the team, not AppSec staff.

| Champions do | Champions do not |
|---|---|
| Keep `.security/application.yaml` and the threat model current | Approve their own team's exceptions or classifications |
| Register the application and wire the pipeline | Own every finding (the team does) |
| Triage new findings within {{TRIAGE_DAYS}} days, request false positives with evidence | Replace AppSec reviews for Tier 1/2 |
| Run the SAMM self-assessment (M1) and arrange the independent review (M2) | |

## Onboarding (first month)

1. Course: {{COURSE_NAME}} (recorded as training evidence when the LMS connector is set up).
2. Walk through your application in the platform with an AppSec engineer: tier, gaps, findings, evidence.
3. Grant: a platform admin gives you the `champion` role scoped to your team (Admin → Role grants).

## Community

{{CADENCE, e.g. monthly}} champions' meeting; a channel ({{CHANNEL}}) where platform notifications for approvals and
P1 findings arrive.
