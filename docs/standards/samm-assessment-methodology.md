# SAMM Assessment Methodology (process)

| | |
|---|---|
| Status | DRAFT, REQUIRES HUMAN APPROVAL |
| Owner | Head of Application Security. Operated by Security Governance. |
| Calculation | [SAMM/ASVS mapping section A.3](samm-asvs-mapping.md#a3-maturity-calculation), [`config/maturity-methodology.yaml`](../../config/maturity-methodology.yaml), targets [`config/samm-targets.yaml`](../../config/samm-targets.yaml) |

This document covers **how assessments are run**. The calculation is defined in the SAMM/ASVS mapping document and the configuration above.

## 1. Assessment types

| Type | Scope | Frequency | Assessors | Evidence |
|---|---|---|---|---|
| Continuous automated | Every application | Continuous | Platform | C1–C3 control states |
| Application assessment | One application (non-automatable activities only) | Annually: Tier 1 (M2), Tier 2 (M1 + AppSec sample), Tier 3 (sampled 10%) | Champion + AppSec engineer | M1/M2 |
| Organisational assessment | Governance practices (G-SM, G-PC, G-EG) and programme-level parts of others | Annually | Governance analyst + AppSec lead. External reviewer optional. | M2 |
| Baseline | First applications + organisation | At adoption | AppSec | M2 |

## 2. Application assessment procedure

1. **Plan** (platform creates the assessment 30 days before due): scope = the application, its repositories and the target profile for its tier.
2. **Pre-fill**: the platform pre-populates every SAMM question that has mapped controls with the automated answer, read-only, with the control states and evidence behind it.
3. **Interview** (60–90 min): champion + tech lead + AppSec assessor answer only the remaining questions, using the **official SAMM question text and answer options**. Each answer needs a rationale. Evidence references are expected for answers ≥ 0.5.
4. **Cap**: where a manual answer exceeds the automated answer by more than the tolerance, it is capped and flagged ("evidence does not support this answer").
5. **Submit and approve**: approver ≠ lead assessor. M2 needs an approver outside the team. Approval creates `assessment.samm_interview` evidence (valid 365 days).
6. **Improvement plan**: for each practice below target, the team records 1–3 improvement actions (Jira-linked). The platform suggests actions from the gaps in mapped controls.

## 3. Organisational assessment procedure

Document review (charter, standards, KPI packs, training records, champion programme) → interviews with Security Governance, AppSec, two business unit leads and three champions → answers for Governance practices plus programme-level parts of other practices → Board review → published as an organisation-scope assessment.

## 4. Quality controls

| Control | Detail |
|---|---|
| Official text only | Questions and options are imported verbatim. Never paraphrased in the UI. |
| Calibration | Quarterly: AppSec manually checks 5% of automated SATISFIED states (EVD-04 ≥ 97%) |
| Assessor consistency | Annual calibration workshop. Two assessors double-score three apps and compare. |
| Methodology change | Recorded in the snapshot. Trend charts mark discontinuities. |
| Use restrictions | Scores are reported as distributions with provenance. No league tables. Never used for individual performance (charter constraint). |

## 5. Outputs

Application maturity report (practice/stream scores, target comparison, provenance, improvement actions) · business unit roll-up (distribution, % meeting target) · organisation report (Governance practices plus application distributions, trend).
