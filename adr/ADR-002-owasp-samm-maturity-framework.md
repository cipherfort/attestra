# ADR-002: OWASP SAMM as the maturity framework

**Status:** Proposed (2026-10-07)  ·  **Related:** [SAMM/ASVS methodology](../docs/standards/samm-asvs-mapping.md), [`catalogue/frameworks/samm.yaml`](../catalogue/frameworks/samm.yaml)

## Context

Leadership needs a maturity model that is recognised, open, prescriptive enough to drive improvement, and measurable. Several models exist with different purposes.

## Decision

Adopt **OWASP SAMM 2.0** (version to be confirmed at Phase 0 import) as the primary maturity framework, with these rules:

1. SAMM structure, activity text and assessment questions are **imported verbatim** from the official model at a pinned version and displayed unmodified. Platform documentation paraphrases only for orientation and labels the paraphrase.
2. Maturity is **derived**: automated control states feed SAMM answers where a mapping exists. Manual answers fill the rest and are capped by contrary automated evidence ([methodology section A.3](../docs/standards/samm-asvs-mapping.md#a3-maturity-calculation)).
3. Assessment happens at **two scopes**: organisation (Governance practices) and application (the rest).
4. Every score shows its **evidence mix** (automated / independent manual / self / unassessed).

## Alternatives considered

| Option | Assessment |
|---|---|
| **BSIMM** | Descriptive (what others do), not prescriptive. Benchmark data needs participation. Less suited to driving team-level improvement. |
| **NIST SSDF** alone | Excellent practice taxonomy (we map to it) but has **no maturity levels**. |
| **OWASP DSOMM** | Strong on pipeline activities, narrower overall. Used as *inspiration* for automatable controls, not as a second maturity score (two scores would confuse leadership). |
| **OpenSSF Scorecard** | Repository hygiene checks, useful as *evidence input* (PROPOSED connector), not a maturity model. |
| Internal bespoke model | Not recognised externally. Hard to defend. Reinvents SAMM. |

## Decision drivers

Open and free · prescriptive levels per practice · widely recognised · fits the evidence model (activities are mappable to controls).

## Consequences

- SAMM was designed for organisation-level assessment. Per-application scores are an organisational adaptation and are documented as such.
- When SAMM releases a new model version, we re-import, re-map and record a methodology change in snapshots. Trend lines show a discontinuity marker rather than a false jump.
- Some practices (Strategy & Metrics, culture) remain mostly manual. That is accepted and shown honestly in the coverage matrix.

## Security implications

None directly. Misrepresenting maturity is a governance risk, mitigated by provenance display and quarterly calibration audits.

## Operational implications

Annual organisational SAMM assessment. Annual application manual questions for Tier 1/2. A model importer to maintain.
