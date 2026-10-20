# Application Security Strategy 2026–2028

| | |
|---|---|
| Status | DRAFT for CISO approval |
| Owner | AppSec lead |
| Horizon | 18–24 months, reviewed annually |

## 1. Vision

**Every application the organisation builds is secure by default and can prove it.** Engineering teams get security through the tools they already use. Leadership sees evidence-backed risk and maturity, not self-assessment.

## 2. Strategic objectives

| # | Objective | Measure (see [KPI catalogue](../../docs/standards/kpi-kri-catalogue.md)) |
|---|---|---|
| SO1 | **Know the estate:** every production application registered, owned and classified | COV-01, KRI-04, KRI-05 |
| SO2 | **Secure by default:** a paved-road pipeline adopted across the estate | COV-02, PIP-01…05 |
| SO3 | **Fix what matters first:** contextual prioritisation, remediation verified | VUL-02, VUL-03, KRI-01, KRI-02 |
| SO4 | **Design security in:** threat modelling and architecture review for critical apps | COV-04 |
| SO5 | **Evidence-backed maturity:** SAMM maturity derived from evidence, improving year on year | MAT-01, EVD-03 |
| SO6 | **Resilient supply chain:** provenance, SBOMs, hardened CI | PIP-03, ASC-BLD-06/09 |
| SO7 | **A security culture led by engineers:** a champion in every team | PPL-01, PPL-02 |

## 3. Strategic choices

| We will | We will not |
|---|---|
| Use the tools we already own (GHAS, Defender, Sentinel, DT, DefectDojo) and connect them | Buy overlapping scanners per team |
| Measure controls operating, coverage and speed of verified remediation | Rate teams on finding counts |
| Introduce gates gradually, per tier, after observing | Block delivery on day one |
| Keep risk acceptance explicit, time-bound and owned | Accept tool-level "risk accepted" flags |
| Align with OWASP SAMM, ASVS and NIST SSDF | Invent a bespoke framework |
| Keep internal security evidence internal, even for open-source code | Publish findings with public code |

## 4. Pillars and initiatives

| Pillar | Initiatives (programme epics) |
|---|---|
| Visibility | Application discovery and registry (E02, E03), cloud attribution (E15) |
| Prevention | Paved-road pipeline (E07), GitHub baseline (STD-12), supply-chain standard (STD-09) |
| Assurance | Evidence engine (E08), control catalogue (E05), SAMM/ASVS (E04, E12), threat modelling (E11) |
| Response | Risk engine (E13), vulnerability management (E09), Jira (E14), SOC events (E18), CVE response (E10) |
| People | Champions (E17), training (ASC-GOV-04), guidance (E21) |
| Governance | Board, standards, exceptions, reporting (E01) |

## 5. Risks to the strategy

Adoption resistance, capacity, data quality, and the one-time privileged bootstrap steps the project performs itself ([ADR-031](../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md)). See the [risk register](../programme/risk-register/risk-register.md) R-01–R-06.

## 6. Review

Annual strategy review in the Security Leadership Review, informed by the organisational SAMM assessment and KPI trends.
