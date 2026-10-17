# ADR-018: Jira integration

**Status:** Proposed (2026-10-07), amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** [Platform architecture section 5.3](../docs/architecture/02-platform-architecture.md#53-finding-lifecycle), [Data model section 4](../docs/architecture/03-data-model.md#4-deduplication-identities-fingerprints)

## Context

Engineers work in Jira. Every pipeline run must not create duplicate tickets. DefectDojo has native Jira push, but it uses tool severity (not contextual priority), knows nothing of control gaps or expired exceptions, and would make two systems write tickets.

## Decision

1. **The platform is the only system that creates security tickets.** DefectDojo's Jira integration is **disabled** for platform-managed products.
2. **What gets a ticket:** P1–P3 findings after auto-triage. Control gaps past the grace period. Expired exceptions. P4 findings are batched into a monthly per-app hygiene ticket (optional per team).
3. **Deterministic dedup keys** (`tickets.dedup_key`, unique):
   - dependency: `dep|<app>|<repo>|<purl without version>`, grouping all CVEs fixed by one upgrade;
   - container: `ctr|<app>|<image name>|<base image or package>`;
   - other findings: `fnd|<finding fingerprint>`;
   - control gap: `gap|<app>|<control_key>`.

   The key is stored in a Jira custom field / entity property. Lookup happens **before** create, so a crash between create and store is reconciled by a JQL search on the property.
4. **Ticket content:** title, priority (platform priority → Jira priority), due date (SLA), labels (`appsec`, `aap-P1`, control key, CWE), minimal detail plus a deep link to the platform. **No exploit detail or secret material in Jira.** A Jira issue-security level restricts visibility to the team plus security (set by the project's Jira site admin, runbook step 9).
5. **Status sync (one way for closure):**
   - Jira "Done" → finding `fix_pending` → **the platform requests verification** (re-scan via `workflow_dispatch`, or waits for the next push/scheduled scan).
   - Verification passes → finding `verified` → `closed`, with a comment on the ticket.
   - Verification fails → the ticket is **re-opened** with a comment ("still detected in run X").
   - A finding that disappears on re-scan while the ticket is open → auto-transition to Done with an evidence link.
6. **Routing:** Jira project/component per app from `application.yaml` (`jira_project`, default = the business unit's security project). Assignee = technical owner or champion.
7. **Sync mechanism:** Jira webhooks as hints, plus polling via JQL `updated >= -15m` on platform-managed issues. Rate limiting and backoff included.
8. **Auth:** Jira Cloud via a service account API token stored by `aap bootstrap jira`; Jira Data Center via PAT. The site, project and service account are created by the project (ADR-031). IMPLEMENTED: `connectors/jira.py`, `services/ticketing.py`. Idempotency uses a deterministic label `aap-k-<hash>` because entity properties are not JQL-searchable without a Jira app.

## Alternatives considered

| Option | Why not |
|---|---|
| DefectDojo native Jira push | Tool severity. No control gaps. Two ticket writers. Weaker grouping. |
| One ticket per CVE instance | Floods teams. Five CVEs in one package should be one upgrade task. |
| GitHub Issues | Not where most teams plan work (confirm). Possible future adapter behind the same interface. |
| ServiceNow | Possible adapter later. Interface is ticket-system agnostic. |

## Decision drivers

No duplicates · contextual priority · closure by evidence · minimal sensitive data in Jira.

## Consequences

The workflow mapping per Jira project needs configuration (status names differ). Teams with custom workflows need a mapping entry.

## Security implications

Jira is a wider-audience system, hence minimal detail plus issue security levels (threat T-11). Ticket closure cannot close a finding, which defeats "close the ticket to make the number go down".

## Operational implications

Jira API quotas. Reconciliation job. Mapping maintenance per project.
