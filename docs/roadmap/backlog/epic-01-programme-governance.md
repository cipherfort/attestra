# E01: Programme Governance

**Goal:** Decisions, accountability and reporting cadence are in place so the platform has authority and direction.

## F01: Governance forums

### E01-F01-S01: Stand up the AppSec Governance Board · M · Phase 0
- **Story:** As AppSec lead, I want a Board with agreed ToR and membership so that catalogue, risk-model and exception decisions have a legitimate forum.
- **Value:** Decisions stop being ad hoc. The catalogue gains authority.
- **Technical:** ToR document. Decision log in the repo (`adoption-kit/governance/decision-log.md`). Board pack template.
- **Depends on:** Charter sign-off (E01-F02-S01).
- **AC:** Given the ToR is approved, when the first Board meets, then membership, quorum, decision rights and escalation are minuted, and the decision log has its first entries.
- **Security:** Board packs contain aggregated data only, classified Internal.
- **Tests:** n/a (process). PO verifies the artefacts.
- **Tasks:** draft ToR · confirm members · schedule cadence · create decision-log template · first meeting.

### E01-F01-S02: Approve catalogue v0.2, tier model, risk model and SLAs · M · Phase 0
- **Story:** As the catalogue owner, I want the Board to approve the Stage 1 control catalogue and models so that evaluation can begin on agreed rules.
- **Value:** Removes the largest source of later rework.
- **Technical:** PRs against `catalogue/` and `config/`. Rendered catalogue for review.
- **Depends on:** E01-F01-S01.
- **AC:** Every item marked "REQUIRES HUMAN APPROVAL" in catalogue/config is approved, amended or deferred, with a decision-log reference. `catalogue_version` bumped to 0.2.0.
- **Security:** Changes via signed, reviewed PRs only (T-12).
- **Tests:** `tools/catalogue/validate.py --check` green.
- **Tasks:** walkthrough sessions (AppSec, champions, cloud security) · collect amendments · Board decision · merge.

## F02: Programme mandate

### E01-F02-S01: Charter and PID sign-off · M · Phase 0
- **Story:** As sponsor, I want to approve the charter and PID so that the team is resourced and scope is agreed.
- **AC:** Signed charter (version, date, approver). Resource commitments recorded. Decisions in charter section 19 answered.
- **Tasks:** leadership walkthrough · revisions · sign-off.

### E01-F02-S02: Policy statement mandating application registration · M · Phase 0–2
- **Story:** As CISO, I want a policy requiring production applications to be registered so that coverage targets are enforceable.
- **AC:** Policy published. Effective date set. Exception route defined (via platform exceptions).
- **Tasks:** draft · consult business units · publish · communicate.

## F03: Programme reporting

### E01-F03-S01: Backlog import to Jira and RAID log · S · Phase 0
- **Story:** As PO, I want this backlog in Jira and a RAID log so that delivery is tracked in the organisation's tools.
- **Technical:** Script parses `docs/roadmap/backlog/epic-*.md` → Jira issues (Epic/Story/Sub-task), idempotent by story ID in a custom field.
- **AC:** Re-running the import creates no duplicates. Every story ID maps to exactly one issue.
- **Security:** Jira token from Key Vault or local env, never committed.
- **Tests:** Parser unit tests on sample markdown. Dry-run mode.
- **Tasks:** parser · Jira field mapping · dry-run · import.
