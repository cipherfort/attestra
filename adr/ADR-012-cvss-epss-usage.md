# ADR-012: Use of CVSS, EPSS and CISA KEV

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-011

## Context

CVSS, EPSS and KEV answer different questions and are often misused interchangeably.

| Signal | Answers | Does not answer |
|---|---|---|
| **CVSS** (v4.0 / v3.1) | Technical severity characteristics of a vulnerability in general | Probability of exploitation; our context |
| **EPSS** (FIRST, v4 current) | Estimated probability of exploitation *activity* in the wild in the next 30 days, per CVE, global | Whether *our* deployment is exploitable; non-CVE findings |
| **CISA KEV** | Confirmed exploitation in the wild | Absence from KEV ≠ not exploited |

## Decision

1. **CVSS** characterises a finding (display, exploitability sub-score as a likelihood fallback, impact metrics for integrity modifiers). **CVSS v4 is preferred when available**, else v3.1. Vectors are stored, not only scores. CVSS is **never used alone** to set priority.
2. **EPSS percentile** (not raw probability) is the primary likelihood base for CVE-backed findings. It is refreshed daily from the FIRST API/bulk CSV. The EPSS value and date used are **snapshotted** in each risk assessment for reproducibility.
3. **KEV** listing raises likelihood (+2) and forces P1 for internet-facing apps. It is refreshed daily (CISA JSON feed).
4. **Multiple vulnerability sources** (OSV, GHSA, NVD via Dependency-Track, vendor advisories), given NVD enrichment backlogs. Alias resolution picks one canonical ID (CVE > GHSA > OSV).
5. Non-CVE findings (SAST, IaC, DAST) use tool severity mapped to a base, plus context modifiers.

## Alternatives considered

| Option | Why not |
|---|---|
| CVSS ≥ 9 → critical SLA | Large volume of low-real-risk work. Ignores exploitation evidence. |
| EPSS only | Undefined for non-CVE findings. Global, not contextual. |
| Commercial threat intel exploit feeds | Possible future enrichment (adds `exploit_public` fidelity). Not required for v1. |

## Decision drivers

Each signal used for what it measures · reproducibility · no single-metric decisions.

## Consequences

Priority can change daily as EPSS moves. Mitigation: re-scoring only **raises** priority automatically. Lowering waits until the next scheduled weekly re-score, to avoid flapping. SLA clocks do not extend.

## Security implications

Feeds are integrity-checked (TLS, expected schema, sanity bounds: a > 50% drop in KEV entries is rejected and alerted).

## Operational implications

Two daily feed jobs with health metrics. A feed outage shows stale-feed banners rather than silently using old data.
