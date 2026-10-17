# E23: Production Rollout

**Goal:** From pilot to organisation-wide adoption by tier, with gates enabled deliberately.

## F01: Pilot

### E23-F01-S01: Run the pilot (3–5 apps) · M · Phase 9
- **AC:** All 19 pilot demonstration items shown on real repos. Success criteria PS-1 … PS-14 measured and reported ([roadmap](../../../adoption-kit/programme/roadmap/roadmap.md#pilot-phase-9)). A pilot report with go/no-go recommendation goes to the Board.

### E23-F01-S02: Calibration and catalogue tuning from pilot data · M · Phase 9
- **AC:** 30-sample calibration audit (PS-9). Noisy or unfair controls adjusted via catalogue PRs. Risk-model override rate reviewed. Catalogue → v1.0.0.

## F02: Rollout waves

### E23-F02-S01: Wave plan and onboarding support model · M · Phase 10
- **AC:** Waves: Tier 1 (AppSec-assisted) → Tier 2 (assisted) → Tier 3/4 (self-service). Office hours, a Teams channel, an onboarding SLA (onboarding PR < 1 business day). Per-wave entry/exit criteria.

### E23-F02-S02: Gate enablement per wave · M · Phase 10
- **AC:** Gates enabled per the [gating roadmap](../../architecture/05-pipeline-architecture.md#9-gating-roadmap-observe--gate), after ≥ 4 weeks of observe data per wave and Board approval. Bypass via audited ruleset lists only.

### E23-F02-S03: Org ruleset "require aap-security workflow" by tier · S · Phase 10
- **AC:** Org rulesets target repos by the custom property `aap_tier` (set by the onboarding App if approved, else by org admins). Enforcement verified on a canary repo (the workflow cannot be removed without a ruleset bypass). Needs a Team/Enterprise plan (decision D-018); applied by `examples/terraform/azure/envs/github`.
