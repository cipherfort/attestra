# 90-day rollout playbook — {{ORGANIZATION}}

From nothing to every Tier 1 application evidenced, in three 30-day steps. Each step ends with a decision by the
{{STEERING_GROUP}} to continue. Replace every `{{...}}`; keep the exit criteria measurable.

## Days 1–30: foundations and a thin slice

| Week | Do | With the platform | Owner |
|---|---|---|---|
| 1 | Name the sponsor, the platform owner and the AppSec lead; agree the decisions in [`../governance/decision-log.md`](../governance/decision-log.md) (tiers, deadlines, approvers) | — | {{SPONSOR}} |
| 1 | Evaluate the platform with the demo | `deploy/compose/setup.sh` | {{PLATFORM_OWNER}} |
| 2 | Encode your decisions as rules and review them as a pull request | `config/organization.yaml`, `config/profiles/`, `config/exception-policy.yaml`, `catalogue/` | {{APPSEC_LEAD}} |
| 2 | Install for real | Helm chart (`charts/attestra`), your IdP, PostgreSQL, write-once bucket | {{PLATFORM_OWNER}} |
| 3 | Connect source control (read-only) and publish the pipelines | `aap bootstrap github-app` / `aap bootstrap gitlab`; `aap pipelines export` → review → `aap pipelines approve` | {{PLATFORM_OWNER}} |
| 4 | Thin slice: one real repository end to end | Register it, add the caller workflow, see verified evidence change control states | {{PILOT_TEAM}} |

**Exit:** one application registered, its pipeline evidence verified (C2 or C3), its classification approved by AppSec,
and a finding opened by a scan and closed by a re-scan.

## Days 31–60: pilot

| Week | Do | With the platform |
|---|---|---|
| 5 | Choose 3–5 pilot applications across tiers and teams; brief their champions | Admin: units, members, champion grants |
| 5–6 | Register the pilots; approve Tier 1/2 classifications | Register an application; Classification → Approve |
| 6–7 | Turn on tickets for P1–P3 in one project | `config/integrations.yaml` (Jira or GitHub/GitLab Issues) |
| 7 | Record the first manual evidence: one threat model review, one SAMM interview | Assessments |
| 8 | Review exceptions requested so far against the policy; adjust the policy by pull request if it does not fit | Exceptions |

**Exit:** every pilot application has its mandatory automated controls at "satisfied" or a tracked reason; mean time
to triage P1/P2 under {{TRIAGE_TARGET_DAYS}} days; champions can explain their application's tier and top gap.

## Days 61–90: rollout to all Tier 1, then by tier

| Week | Do |
|---|---|
| 9 | Publish the onboarding guide for teams ([user guide](../../docs/guide/user-guide.md)) and the champion expectations ([`champion-framework.md`](champion-framework.md)) |
| 9–12 | Onboard every Tier 1 application; weekly clinic for champions |
| 10 | Connect the SIEM and notifications; agree the alert owners ({{SOC_CONTACT}}) |
| 12 | First quarterly report to the {{STEERING_GROUP}} from the Leadership page; set the Tier 2 schedule |

**Exit:** {{TIER1_COUNT}} Tier 1 applications registered with current evidence; KPIs in
[`../../docs/standards/kpi-kri-catalogue.md`](../../docs/standards/kpi-kri-catalogue.md) reported from the platform, not
spreadsheets.

## Measures to watch from day 1

- Mandatory control coverage (proven / required), by tier.
- P1 open past SLA (should be 0), KEV-listed vulnerabilities on internet-facing applications.
- Evidence rejections (a spike means a team is bypassing the approved pipeline, or the pipeline release broke).
- Exceptions: count, age, renewals.
