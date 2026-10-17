# Governance — {{ORGANIZATION}}

| Forum | Members | Cadence | Decides |
|---|---|---|---|
| {{STEERING_GROUP}} | {{SPONSOR}}, {{APPSEC_LEAD}}, unit leads, {{PLATFORM_OWNER}} | {{QUARTERLY}} | Targets, scope, disputes, risk acceptance above policy |
| Rules review | {{APPSEC_LEAD}}, AppSec engineers, a champion | Per pull request | Changes to controls, tiers, risk model, exception policy (merged = in force) |
| Platform change | {{PLATFORM_OWNER}}, AppSec | Per release | Platform upgrades, pipeline releases (trusted producers) |

## Records

Everything the platform decides is recorded where auditors can read it:
- rules: git history of `config/` and `catalogue/` (who approved what, when);
- approvals and refusals: the audit log (hash-chained);
- evidence: the evidence ledger (hash-chained, write-once storage, daily checkpoint exported to {{SIEM}}).

## Escalation

An exception above the policy's maximum, a disputed classification, or a team that cannot meet a deadline goes to the
{{STEERING_GROUP}} with the platform's evidence page as the briefing.
