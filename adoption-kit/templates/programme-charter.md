# Application security assurance programme: charter — {{ORGANIZATION}}

| | |
|---|---|
| Sponsor | {{SPONSOR}} ({{SPONSOR_ROLE}}) |
| Programme owner | {{PROGRAMME_OWNER}} |
| Platform owner | {{PLATFORM_OWNER}} |
| AppSec lead | {{APPSEC_LEAD}} |
| Approved on | {{DATE}} by {{STEERING_GROUP}} |

## Why

{{ONE_PARAGRAPH: the problem in your words, e.g. "we cannot show which of our N applications are built and run
securely, or prove it to {{REGULATOR/AUDITOR/BOARD}}".}}

## Objective

Every application in scope has its required security controls proven by current evidence, its risks prioritized and
owned, and exceptions approved and time-bound, within {{TIMEFRAME}}.

## Scope

- In: {{APPLICATIONS_IN_SCOPE, e.g. all applications owned by {{BUSINESS_UNITS}}; source control: {{GITHUB/GITLAB}}}}.
- Out: {{OUT_OF_SCOPE, e.g. third-party SaaS without our code, end-user devices}}.

## Success measures

| Measure | Baseline | Target | By |
|---|---|---|---|
| Tier 1 applications with all mandatory controls proven | {{N}} | 100 % | {{DATE}} |
| P1 findings past SLA | {{N}} | 0 | {{DATE}} |
| Applications registered | {{N}} | {{N}} | {{DATE}} |

## Decision rights

Rules (tiers, deadlines, controls, exception approvers) change by pull request approved by {{RULE_OWNER}}. Exceptions
are approved per `config/exception-policy.yaml`. Disputes go to {{STEERING_GROUP}}, which meets {{CADENCE}}.

## Constraints and assumptions

{{e.g. no new headcount; evidence storage retention {{YEARS}} years; one deployment per organization}}
