# Application Classification Standard

| | |
|---|---|
| ID | STD-02 · Status: DRAFT, REQUIRES HUMAN APPROVAL (tier labels, thresholds, ASVS targets) |
| Owner | Head of Application Security |
| Configuration | [`config/profiles/<profile>/classification.yaml`](../../config/profiles/generic/classification.yaml) (authoritative) |
| Review | Annually. Model changes by PR plus Governance Board approval. |

## 1. Purpose

Assigns every application a risk tier that determines its security requirements, its evidence expectations, its risk-model impact and who may approve exceptions for it.

## 2. Tiers

| Tier | Label (configurable) | Meaning | ASVS target | Typical examples |
|---|---|---|---|---|
| 1 | Critical | High-impact public services, sensitive data at scale, or critical business functions | L3 | National citizen-facing services. Identity or cloud-admin tooling. |
| 2 | High | Significant operational or information-security impact | L2 | Internet-facing services with citizen data. Core internal systems. |
| 3 | Standard | Normal business applications | L1 + automatable L2 | Internal line-of-business apps |
| 4 | Low | Low-risk, limited-impact, prototypes | L1 | Internal tools without sensitive data, time-limited prototypes |

## 3. Method

Owners answer seven questions in `application.yaml`: data classification, personal data, exposure, user population, business criticality, privileged integration, and regulatory obligations. The platform computes the tier in two steps:

1. **Floor rules.** Any match sets a minimum tier. For example, FR-1 (internet-facing + special-category personal data) gives at least Tier 1, and FR-2 (high-privilege integration) gives at least Tier 1.
2. **Points.** Dimension scores are summed and mapped to a tier (≥ 16 → T1, ≥ 10 → T2, ≥ 4 → T3, else T4).

The final tier is the more critical of the two. The platform shows the inputs, the matched rules, the points and the model version ("why is my app Tier 1?").

## 4. Requirements

| ID | Requirement | Proven by |
|---|---|---|
| CLS-01 | Every application shall be classified before onboarding completes and before production release | ASC-GOV-02 |
| CLS-02 | Tier 1 and Tier 2 classifications shall be approved by an AppSec engineer | ASC-GOV-02 (M2) |
| CLS-03 | Classification shall be re-attested at least every 12 months, and whenever a classification input changes in `application.yaml` | event_bound freshness on `registry.classification` |
| CLS-04 | A tier lower than the computed tier requires an override approved by AppSec (AppSec lead for Tier 1/2 → lower). The computed tier applies until then. | Workflow + abuse case AC-09 |
| CLS-05 | Where cloud inventory shows greater exposure than declared, the **more exposed** value shall be used | Exposure verification (E15-F03-S02) |
| CLS-06 | Prototypes shall not process real personal data. A prototype that does must be reclassified. | Attestation + floor rules |

## 5. Data classification labels

Labels in `config/profiles/<profile>/classification.yaml` (`public`, `internal`, `confidential`, `highly_confidential`) are placeholders. They **shall be mapped to the organisation's information classification scheme** by Information Governance before go-live (REQUIRES HUMAN APPROVAL). Code depends only on rank, never on label text.

## 6. Exceptions

Classification itself cannot be excepted (it is the basis for everything else). Disputes go to the Governance Board.
