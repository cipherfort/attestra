# Security Requirements Standard

| | |
|---|---|
| ID | STD-03 · Status: Template. Adapt it and have it approved in your organization. |
| Owner | AppSec lead |
| Framework | OWASP ASVS 5.0 (official requirement text imported verbatim, never paraphrased) |
| Related | [ASVS Implementation Guide](../guides/asvs-implementation-guide.md), [SAMM/ASVS methodology Part B](samm-asvs-mapping.md#part-b-owasp-asvs-operational-not-a-checklist) |

## 1. Purpose

Defines which technical security requirements apply to an application, and how their verification is evidenced.

## 2. Requirements

| ID | Requirement | Proven by |
|---|---|---|
| REQ-01 | Each application (Tier 1–3) shall maintain `.security/asvs.yaml` declaring the ASVS version, a target level ≥ its tier target, and its capability profile | ASC-REQ-01 |
| REQ-02 | Applicable requirements shall be derived by the platform from the capability profile ([applicability map](../../catalogue/frameworks/asvs-applicability.yaml)). Teams shall not hand-pick requirements. | Platform instantiation |
| REQ-03 | Requirements may be marked N/A only with a written justification, approved in the platform (by AppSec for Tier 1) | Approval workflow |
| REQ-04 | Tier 1/2 applications shall have ≥ 80% of applicable requirements VERIFIED by evidence (Tier 3: 50%, recommended) | ASC-REQ-02 |
| REQ-05 | A requirement is VERIFIED only by: a passing automated test tagged with the requirement ID, a configuration check, or an independent manual review/pen test record. **Scanner silence is not verification.** | Requirement-status rules |
| REQ-06 | Requirements arising from threat models, regulation or contracts shall be recorded as `custom_requirements` with a verification method | asvs.yaml schema |
| REQ-07 | Suppliers developing for us shall be contractually bound to the same ASVS level for the application's tier | ASC-REQ-03 (manual) |
| REQ-08 | Mobile applications shall additionally follow OWASP MASVS (planned for when the first mobile application is onboarded) | Future control |

## 3. Requirement status values

`verified` · `scanned_no_issues` (supporting only) · `failed` (open finding mapped to the requirement's CWE) · `unverified` · `excepted` · `not_applicable`.

## 4. Exceptions

An exception against a requirement uses the standard process with `target_type: requirement`. Expiry reopens the requirement as `failed`.
