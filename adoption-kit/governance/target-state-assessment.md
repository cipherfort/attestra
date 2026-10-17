# Target State Assessment (18 months)

| | |
|---|---|
| Status | DRAFT. Targets PROPOSED for Governance Board approval. |
| Related | [Current state](target-state-assessment.md), [Roadmap](../programme/roadmap/roadmap.md), [`config/samm-targets.yaml`](../../config/samm-targets.yaml), [KPI catalogue](../../docs/standards/kpi-kri-catalogue.md) |

## 1. Target capability profile

| Capability | Current (expected) | Target (18 months) | What "good" looks like | Primary measure |
|---|---|---|---|---|
| Application inventory and ownership | 0 | 3 | ≥ 90% of production apps registered. Owners resolve. Dark apps < 5%. | COV-01, KRI-04 |
| Risk classification | 0 | 3 | All apps tiered. Tier 1/2 approved. Annual re-attestation. | ASC-GOV-02 |
| Security requirements | 0–1 | 2 | ASVS profiles for Tier 1–3. Tier 1/2 ≥ 80% verified. | ASC-REQ-02 |
| Threat modelling | 0–1 | 2–3 | All Tier 1/2 with current reviewed models | COV-04 |
| Secure build | 1 | 3 | Paved road on ≥ 90% active repos. SBOM + provenance for Tier 1/2. | COV-02, PIP-* |
| Vulnerability management | 1 | 3 | Contextual priority. P1 SLA ≥ 95%. Closure by evidence. | VUL-02/03 |
| Risk acceptance | 0 | 3 | All exceptions governed. No expired exceptions unremediated. | VUL-06, KRI-03 |
| Evidence and audit | 0 | 3 | ≥ 75% satisfied controls backed by C2/C3. Daily integrity verified. | EVD-01…04 |
| Cloud posture linkage | 0 | 2 | < 20% unattributed. Cloud findings in SLA flow. | KRI-06 |
| SOC integration | 0 | 2 | 11 event types live. Analytics rules deployed. | — |
| Champions and training | 0–1 | 2 | ≥ 90% team coverage | PPL-01/02 |
| Metrics and reporting | 0 | 3 | Monthly packs generated from the platform without manual assembly | Charter exit criteria |

## 2. Target SAMM profile

Organisation-level targets in the [roadmap](../programme/roadmap/roadmap.md#18-month-maturity-roadmap-targets-proposed-organisation-level-evidence-backed). Per-tier application targets in [`config/samm-targets.yaml`](../../config/samm-targets.yaml). Headline: **% of Tier 1 apps meeting target** (MAT-01).

## 3. Gap-closure map

| Gap | Closed by |
|---|---|
| No inventory | E02, E03 |
| No control model | E05 (catalogue v1.0 after pilot) |
| No evidence | E06, E07, E08 |
| Severity-driven triage | E09, E13 |
| Ungoverned exceptions | E09-F03, ADR-021, STD-10 |
| No CVE impact answer | E10 |
| No maturity measurement | E04, E12 |
| Scaffold weaknesses (CS-1–7) | ADR-005/006 (keys removed), ADR-025 follow-up for DD/DT networking |
