# E17: Security Champions

**Goal:** A champion in every team, trained and supported, with participation visible at team level.

## F01: Programme design

### E17-F01-S01: Security Champions Framework · M · Phase 2
- **Story:** As AppSec lead, I want a documented framework (role, time allocation ~10%, nomination, onboarding curriculum, community cadence, recognition), so that champions are a sustained capability.
- **AC:** Framework document (Stage 3 doc #20) approved by the Board. Curriculum: threat modelling, triage, secure code review, platform use, ASVS tagging. Training requirements per tier.

### E17-F01-S02: Champion onboarding course in the LMS · S · Phase 2–6
- **AC:** Course key `champion-onboarding`. Completion feeds `training_records` (CSV import until the LMS connector exists). ASC-GOV-03 evaluates it.

## F02: Platform support

### E17-F02-S01: Champion registry and activity tracking · M · Phase 6
- **AC:** `security_champions` from `application.yaml` + nominations. Activities recorded automatically where possible (threat-model reviews, triage actions, FP confirmations) and manually otherwise. Team-level metrics: coverage, participation. **No individual leaderboard** (TOM principle).

### E17-F02-S02: LMS connector · C · Phase 11
- **AC:** Automated completion import (replaces CSV). Identity matching via Entra OID.
