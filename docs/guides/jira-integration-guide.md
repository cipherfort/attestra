# Jira Integration Guide

| | |
|---|---|
| Audience | Jira administrators, team leads, champions |
| Status | IMPLEMENTED (`connectors/jira.py`, `services/ticketing.py`). Setup: `aap bootstrap jira` by the project's Jira site admin (runbook step 9). |
| Decision | [ADR-018](../../adr/ADR-018-jira-integration.md) |

## 1. How it works for teams

- The platform creates tickets for **P1–P3 findings, control gaps past grace, and expired exceptions**. P4 can be batched monthly (per-app setting).
- **One ticket per fix unit**: for example, one "Upgrade jackson-databind" ticket covers every CVE that upgrade fixes.
- The ticket carries priority, due date (SLA), labels and a link to the platform. Exploit detail and secrets are **never** put in Jira.
- **Moving the ticket to Done does not close the finding.** The platform asks for a re-scan. If the issue is gone, the finding closes and the ticket gets a confirmation comment. If it is still there, the ticket is **reopened** with the run link.
- Do not create duplicate tickets by hand. Comment on the platform ticket instead.

## 2. Jira configuration (admins)

| Item | Requirement |
|---|---|
| Edition and auth | Jira Cloud: service account + API token, or an OAuth 2.0 app. Jira Data Center: PAT for a service user. The token is stored in the platform's secret store (`aap secrets put jira-api-token`). |
| Projects | Use each team's project (mapped per app) or one security project per business unit (default) |
| Issue type | `Security Finding` (or `Bug` with label `appsec`) |
| Custom field / entity property | `AAP Dedup Key` (text, hidden from create screens). Used for idempotent create and reconciliation. |
| Priority mapping | P1 → Highest, P2 → High, P3 → Medium, P4 → Low (configurable per project) |
| Due date | Set from SLA |
| Issue security level | `Security - team + AppSec` restricting visibility to the owning team and security roles |
| Workflow mapping | Platform needs: an "in progress" status, a "done" status category, and a reopen transition. The mapping is per project. |
| Webhook (optional) | Issue updated → platform webhook receiver (JWT/shared secret). Polling covers missed events. |
| Service account permissions | Browse, create, edit, transition, comment, set issue security on mapped projects only |

## 3. Platform configuration per application

In the platform (Application → Settings): `jira_project`, optional `jira_component`, `p4_ticket_batching`. This is not stored in `application.yaml`, because it is platform-owned and avoids leaking Jira structure into public repos.

Example project mapping (platform config):
```yaml
jira:
  base_url: https://example.atlassian.net
  projects:
    CLAIMS:
      issue_type: Security Finding
      done_statuses: [Done, Closed]
      reopen_transition: Reopen
      security_level: "Security - team + AppSec"
      priority_map: { P1: Highest, P2: High, P3: Medium, P4: Low }
```

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Ticket reopened after Done | The re-scan still detects the issue. Open the linked run in the ticket comment. |
| No ticket for a finding | P4 (batched), or still within triage, or covered by an exception. Check the finding page. |
| Duplicate tickets | Report to the platform team. Dedup keys are unique, so a duplicate indicates a manual ticket or a mapping change. |
