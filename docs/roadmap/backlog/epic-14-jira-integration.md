# E14: Jira Integration

**Goal:** Tickets where engineers work, without duplicates, closed only by evidence. Design: [ADR-018](../../../adr/ADR-018-jira-integration.md).

**Progress (Stage 9):** Jira Cloud client, grouped dedup keys, label-based idempotency (crash-safe), closure only by evidence, regression reopen, `aap bootstrap jira` IMPLEMENTED (contract fake + opt-in live test). P4 hygiene ticket and webhook hints remain.

## F01: Ticket creation

### E14-F01-S01: Jira adapter and project mapping · M · Phase 8
- **AC:** Adapter interface (create, update, transition, comment, search by entity property). Per-project config: issue type, priority mapping, status mapping, issue security level. Auth per Jira edition (site and token created by the project: `aap bootstrap jira`). The token is in Key Vault.

### E14-F01-S02: Deterministic dedup and grouping · M · Phase 8
- **Story:** As an engineer, I want one ticket per fixable unit (e.g. one upgrade fixing 5 CVEs), so that my backlog reflects work, not scanner output.
- **AC:** Dedup keys per ADR-018. Lookup before create. Crash-recovery reconciliation via the entity property search. 10 runs → 0 duplicate tickets (PS-6). The ticket body has minimal detail plus a deep link, and **no secrets or exploit detail**.
- **Tests:** Concurrency test (two workers, same key) → one ticket. The unique `tickets.dedup_key` guards it.

## F02: Synchronisation

### E14-F02-S01: Closure by evidence and reopen-on-fail · M · Phase 8
- **AC:** Jira Done → finding `fix_pending` → verification requested (`workflow_dispatch` re-scan if permitted, else next scan). Pass → finding closed + ticket comment. Fail → ticket reopened with run link (PS-7). A finding gone on re-scan → ticket auto-closed with an evidence link.
- **Tests:** End-to-end with a sandbox Jira project.

### E14-F02-S02: Status sync (webhooks + polling) · M · Phase 8
- **AC:** Webhooks as hints. JQL polling every 15 min for managed issues. Workflow differences handled by mapping. Sync error rate metric (R-16).

### E14-F02-S03: SLA due dates and priority updates · S · Phase 8
- **AC:** Due date = SLA. A priority raise updates the Jira priority and adds a comment explaining why (with a link to the explanation).
