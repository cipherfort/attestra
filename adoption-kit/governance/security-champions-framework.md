# Security Champions Framework

| | |
|---|---|
| Status | DRAFT, REQUIRES HUMAN APPROVAL (Governance Board, engineering leadership for time allocation) |
| Owner | AppSec lead. Champions lead (AppSec engineer). |
| Related | ASC-GOV-03, E17, KPI PPL-01 |

## 1. Purpose

Scale application security through engineers embedded in every team who own security day to day, with AppSec as coach and escalation point.

## 2. The role

| Aspect | Definition |
|---|---|
| Who | An engineer in the owning team, nominated by the team lead, agreed with the Business Unit Security Lead |
| Time | ~10% (about half a day per week), protected in team planning |
| Coverage | At least one champion per team owning Tier 1–3 applications. Tier 1 teams: a primary and a deputy. |
| Responsibilities | Lead threat modelling (with AppSec for Tier 1) · triage findings and confirm priorities · first reviewer for security-sensitive PRs (CODEOWNERS on `.security/` and workflows) · maintain `application.yaml`/`asvs.yaml` · ensure the team runs the paved road · raise exceptions properly · share learning |
| Not responsible for | Fixing every finding personally · approving their own team's exceptions or M2 evidence · being the team's only security-aware person |

## 3. Curriculum (onboarding: course key `champion-onboarding`)

| Module | Content | Format |
|---|---|---|
| 1 | Platform and paved road: controls, evidence, priorities, exceptions | 2h workshop |
| 2 | Threat modelling with STRIDE using the repo kit | 3h hands-on |
| 3 | Secure code review: OWASP Top 10 and API Top 10 in our stacks | 3h |
| 4 | ASVS tagging and security tests | 2h |
| 5 | Supply chain: dependencies, Actions, secrets | 1.5h |
| 6 | Incident basics: what to escalate, to whom | 1h |

Annual refresh (2h). Role-based secure-development training for all engineers is tracked separately (ASC-GOV-04).

## 4. Training requirements by tier

| Tier | Champion | All contributors |
|---|---|---|
| 1 | Onboarding + annual refresh + threat-model practicum | Secure development course (annual) |
| 2 | Onboarding + annual refresh | Secure development course (annual) |
| 3 | Onboarding | Secure development course (biennial) |
| 4 | Recommended | Awareness |

## 5. Community and support

Fortnightly community session (trends from the platform: recurring CWEs, new controls, tool changes) · a Teams channel with AppSec response within 1 business day · office hours weekly · quarterly "champions update" from the AppSec lead.

## 6. Metrics (team level only; no individual leaderboards)

Champion coverage (PPL-01) · champion training currency · threat-model reviews led · triage within SLA for the team (ASC-VUL-01) · participation in community sessions. Activities are recorded automatically where possible (`champion_activities`).

## 7. Recognition

Recognition in performance conversations by agreement with engineering leadership (input supplied **by the champion**, not generated from platform data) · conference/training budget · named in quarterly updates with consent.
