# Decision Log

Decisions taken by the AppSec Governance Board and Security Leadership. Architecture decisions are recorded as [ADRs](../../adr/README.md). This log records **governance decisions** (approvals of catalogue, models, policies, exceptions above threshold, gating) and links to ADRs where relevant.

| ID | Date | Forum | Decision | Status | Related |
|---|---|---|---|---|---|
| D-001 | TBC | Security Leadership | Approve programme charter and Phases 0–1 | **Pending** | [Charter](../programme/charter/programme-charter.md) |
| D-002 | TBC | Governance Board | Adopt the Board terms of reference and membership | Pending | [Governance model](governance-model.md) |
| D-003 | TBC | Governance Board | Approve control catalogue v0.2 (from v0.1 draft) | Pending | [Catalogue](../../docs/standards/control-catalogue.md) |
| D-004 | TBC | Governance Board | Approve tier model and ASVS targets | Pending | [`config/profiles/<profile>/classification.yaml`](../../config/profiles/generic/classification.yaml) |
| D-005 | TBC | CISO | Approve risk model and remediation SLAs | Pending | [`config/risk-model.yaml`](../../config/risk-model.yaml) |
| D-006 | TBC | CISO | Approve exception policy and approval thresholds | Pending | [`config/exception-policy.yaml`](../../config/exception-policy.yaml) |
| D-007 | TBC | Records mgmt + DPO | Approve retention periods (prerequisite to locking WORM) | Pending | [ADR-017](../../adr/ADR-017-evidence-retention.md) |
| D-008 | TBC | Governance Board | Build vs buy (ASPM market check) | Pending | [ADR-001](../../adr/ADR-001-platform-purpose-and-scope.md) |
| D-009 | TBC | Governance Board | Approve or reject the write-capable `aap-onboarding` GitHub App | Pending | [ADR-005](../../adr/ADR-005-github-primary-source-integration.md) |
| D-010 | TBC | SOC lead | Approve SIEM event catalogue | Pending | [`config/siem-events.yaml`](../../config/siem-events.yaml) |
| D-011 | TBC | Legal | Approve licence policy | Pending | [`config/licence-policy.yaml`](../../config/licence-policy.yaml) |
| D-012 | TBC | Governance Board | Approve SAMM targets per tier | Pending | [`config/samm-targets.yaml`](../../config/samm-targets.yaml) |
| D-013 | TBC | Governance Board | Approve KPI/KRI targets and thresholds | Pending | [KPI catalogue](../../docs/standards/kpi-kri-catalogue.md) |
| D-014 | TBC | Governance Board | Directorate visibility: anonymised vs named cross-directorate comparison | Pending | [ADR-022](../../adr/ADR-022-multi-directorate-model.md) |
| D-015 | TBC | Security leadership + platform PO | Cloud posture coverage: which management groups / subscriptions / AWS accounts the platform reads | Pending | [ADR-019](../../adr/ADR-019-cloud-integration.md), `examples/terraform/azure` `defender_scopes` |
| D-016 | TBC | CISO + records management | Lock the evidence WORM policy (irreversible) and its period | Pending (Unlocked until decided) | [ADR-016](../../adr/ADR-016-evidence-immutability.md), [ADR-017](../../adr/ADR-017-evidence-retention.md) |
| D-017 | TBC | Head of AppSec | Jira project per directorate vs one security project | Pending (one `SEC` project) | [ADR-018](../../adr/ADR-018-jira-integration.md) |
| D-018 | TBC | Programme sponsor | GitHub plan for the new organization (Enterprise Cloud enables private-repo attestations → C3, organization rulesets, App IP allow list) | Pending | [ADR-031](../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md), risk R-23 |
| D-019 | 2026-10-08 | Platform tech lead | The project creates and owns every integration; nothing assumes another team; the earlier prototype scaffold is reference only | Proposed | [ADR-031](../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) |
