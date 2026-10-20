# KPI / KRI Catalogue (rendered)

> **Generated** from `config/metrics.yaml` by `tools/metrics/render.py`. Do not edit by hand.  
> Status: DESIGNED. Targets and thresholds are PROPOSED and need Governance Board approval.

Design rules: no metric rewards finding fewer issues; every metric is computed by the platform from its ledgers; reporting is at team, application or business unit level, **never per person** ([TOM section 7](../../adoption-kit/governance/target-operating-model.md#7-how-the-tom-avoids-gaming)).

**33 metrics**: 21 KPI, 3 context, 9 KRI.

## Coverage

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| COV-01 | Registry coverage | kpi | Registered production applications ÷ discovered production applications (deployments to prod environments + cloud workloads) | percent | tier_1_2: 100, all: 90 | monthly | appsec_lead | Denominator comes from discovery (E02), not from the registry itself, so not registering does not help. |
| COV-02 | Repository onboarding | kpi | Active repositories (push in 90 days) linked to an application and running a trusted security-workflows pin ÷ active repositories | percent | all: 90 | monthly | platform_po | Archiving active repos to shrink the denominator is visible in the repo-archive trend. |
| COV-03 | Critical applications assessed | kpi | Tier 1 apps with an approved SAMM application assessment in the last 12 months ÷ Tier 1 apps | percent | tier_1: 100 | quarterly | appsec_lead | Assessments require an approver outside the team (M2). |
| COV-04 | Threat-model coverage | kpi | Tier 1/2 apps with ASC-TM-01 and ASC-TM-02 satisfied ÷ Tier 1/2 apps | percent | tier_1: 100, tier_2: 80 | monthly | appsec_lead | Review evidence is bound to the commit of the reviewed files and invalidated by architecture-change signals. |

## Pipeline

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| PIP-01 | SAST coverage | kpi | Applicable repos with ASC-BLD-01 satisfied (fresh C2+ evidence, all detected languages) ÷ applicable repos | percent | tier_1_2: 95, all: 85 | weekly | platform_po | Language coverage is checked against detection, so partial scans don't count as full coverage. |
| PIP-02 | SCA coverage | kpi | Applicable repos with ASC-BLD-02 satisfied ÷ applicable repos | percent | all: 95 | weekly | platform_po | Ecosystem coverage checked against lockfile detection. |
| PIP-03 | SBOM coverage | kpi | Deployed artifact digests with a current, quality-passing build SBOM ÷ deployed artifact digests | percent | tier_1_2: 95 | weekly | platform_po | Quality gate (purl coverage, NTIA elements). Inconclusive SBOMs do not count. |
| PIP-04 | DAST coverage | kpi | Deployed Tier 1/2 web/API apps with ASC-TST-01 satisfied ÷ deployed Tier 1/2 web/API apps | percent | tier_1_2: 90 | monthly | appsec_lead | Scans crawling below threshold are INCONCLUSIVE and do not count. |
| PIP-05 | Secrets protection coverage | kpi | Repos with secret scanning, push protection and validity checks enabled ÷ repos | percent | all: 100 | weekly | platform_po | Read from GitHub settings (C1); enforced by org security configuration. |

## Vulnerability

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| VUL-01 | Open P1/P2 findings | context | Count of open findings by priority (contextual), by business unit | count | – | weekly | appsec_lead | Context only, not a target. Reducing detection would lower it, so it is never used to rate teams. |
| VUL-02 | Mean/median time to remediate (verified) | kpi | Detection → closure by verification evidence, median and p90, by priority | days | P1: 7, P2: 30 | monthly | unit_security_leads | Closure requires re-scan evidence; ticket closure alone does not stop the clock. |
| VUL-03 | SLA compliance | kpi | Findings remediated within SLA ÷ findings that fell due, by priority (excepted findings counted separately) | percent | P1: 95, P2: 90, P3: 90 | monthly | unit_security_leads | Excepted findings are reported alongside, so exceptions can't hide breaches; renewals are tracked (VUL-06). |
| VUL-04 | Recurring vulnerabilities | kpi | Findings reopened (same fingerprint) within 180 days of verified closure ÷ verified closures | percent | all: 5 | quarterly | appsec_lead | Fingerprints are deterministic; regressions are detected automatically. |
| VUL-05 | False-positive rate | context | Findings marked false positive ÷ triaged findings, by team and tool | percent | – | quarterly | appsec_lead | P1/P2 FPs need a second reviewer; quarterly sampling. A high rate triggers tool tuning, not team rating. |
| VUL-06 | Exception health | kpi | Active exceptions by priority, renewals > 1, median age | count | renewals_over_1: 0 | monthly | governance_analyst | Expiry is automatic and creates findings. |

## Maturity

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| MAT-01 | Tier 1 apps meeting maturity target | kpi | Tier 1 apps whose SAMM practice scores all meet config/samm-targets.yaml ÷ Tier 1 apps | percent | baseline_plus_points_at_18m: 30 | monthly | appsec_lead | Manual answers are capped by automated evidence; provenance is shown alongside. |
| MAT-02 | SAMM maturity by practice and business unit | context | Distribution (median, p25–p75) of application practice scores per business unit, plus trend | score_0_3 | – | monthly | appsec_lead | Distributions, not rankings. Methodology changes are marked on trends. |
| MAT-03 | Mandatory control coverage | kpi | Mandatory controls satisfied at required confidence ÷ applicable mandatory controls (observe-mode excluded) | percent | tier_1_2: 90 | weekly | appsec_lead | N/A requires approval; excepted controls don't count as satisfied. |

## Evidence

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| EVD-01 | Evidence freshness | kpi | Evidence supporting mandatory controls in ACTIVE state ÷ total supporting evidence (ACTIVE + EXPIRING + EXPIRED) | percent | all: 95 | weekly | platform_po | Freshness is computed by the platform from policy. |
| EVD-02 | Missing evidence | kpi | Applicable mandatory (app, control) pairs in NO_EVIDENCE state | count | tier_1_2_after_onboarding_grace: 0 | weekly | platform_po | NO_EVIDENCE is treated as worse than findings in all views. |
| EVD-03 | Automated evidence share | kpi | Satisfied control states backed by C2/C3 evidence ÷ satisfied control states | percent | all: 75 | monthly | appsec_lead | Confidence is assigned by the platform, never declared. |
| EVD-04 | Evaluator calibration agreement | kpi | Sampled SATISFIED states confirmed by manual AppSec check ÷ sampled | percent | all: 97 | quarterly | appsec_lead | Random sample chosen by the platform. |

## People

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| PPL-01 | Champion coverage | kpi | Teams owning Tier 1–3 apps with an active, trained champion ÷ such teams | percent | all: 90 | quarterly | appsec_lead | Training completion from LMS, not self-declared. |
| PPL-02 | Secure development training coverage | kpi | Recent contributors with current training ÷ recent contributors, per team (ASC-GOV-04) | percent | all: 90 | quarterly | unit_security_leads | Team level only. |

## Risk

| ID | Metric | Kind | Definition | Unit | Target / threshold | Frequency | Owner | Anti-gaming |
|---|---|---|---|---|---|---|---|---|
| KRI-01 | KEV-listed vulnerabilities open on internet-facing apps | kri | Open findings whose vulnerability is CISA KEV-listed, on apps with exposure internet_* | count | escalate if > 0 for > 7 days | daily | ciso | – |
| KRI-02 | P1 findings past SLA | kri | Open P1 findings with sla_breached | count | escalate if > 0 | daily | ciso | – |
| KRI-03 | Expired exceptions not remediated | kri | exception_expired findings open > 7 days | count | escalate if > 0 | weekly | appsec_lead | – |
| KRI-04 | Dark applications | kri | Registered production apps with no evidence ingested in 30 days ÷ registered production apps | percent | escalate if > 5% | weekly | appsec_lead | – |
| KRI-05 | Unregistered repos with production deployments | kri | Repos deploying to production environments that are not linked to a registered application | count | escalate if > 0 for 14 days | weekly | appsec_lead | – |
| KRI-06 | Unattributed cloud findings | kri | High/critical cloud posture findings not attributable to an application ÷ all such findings | percent | escalate if > 20% | weekly | cloud_security | – |
| KRI-07 | Unmanaged tool suppressions | kri | Tool-level suppressions (DD risk accepted, GHAS dismissed, Checkov skip) without a platform exception | count | escalate if rising 3 consecutive months | monthly | appsec_lead | – |
| KRI-08 | Evidence integrity failures | kri | Daily verification job failures (hash chain or blob mismatch) | count | escalate if > 0 | daily | platform_po | – |
| KRI-09 | Stale connectors | kri | Connectors whose last success is older than 2× their schedule | count | escalate if > 0 for > 24h | hourly | platform_po | – |
