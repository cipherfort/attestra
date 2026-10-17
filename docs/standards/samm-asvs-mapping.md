# SAMM & ASVS: Mapping, Assessment and Maturity Methodology

| | |
|---|---|
| Status | DESIGNED: methodology REQUIRES HUMAN APPROVAL. Maturity targets are PROPOSED. |
| Related | [Control framework](control-framework.md), [Control catalogue](control-catalogue.md), [ADR-002](../../adr/ADR-002-owasp-samm-maturity-framework.md), [ADR-003](../../adr/ADR-003-owasp-asvs-requirements.md) |

> **Official vs organisation-specific.** The "Intent" and "L1/L2/L3" columns below are **short paraphrases for orientation only**. The authoritative activity descriptions, assessment questions and answer options come from the official OWASP SAMM model, imported at a pinned version ([`catalogue/frameworks/samm.yaml`](../../catalogue/frameworks/samm.yaml)). The UI shows the official text. Everything in the "Controls", "Automation", "Evidence", "Assessment" and "Improvement" columns is **organisation-specific**.

## Part A: OWASP SAMM

### A.1 What SAMM measures, and at what level

SAMM assesses an organisation's (or a unit's) software assurance practices. Some practices are naturally **organisation-level** (Strategy & Metrics, Policy & Compliance, Education & Guidance). Others are exercised **per application** (Threat Assessment, Secure Build, Security Testing). The platform therefore assesses at two levels:

| Assessment scope | Practices | Source |
|---|---|---|
| **Organisation / directorate** | G-SM, G-PC, G-EG (and the programme-level parts of others) | Annual SAMM interview (M2) with governance evidence |
| **Application** | D-TA, D-SR, D-SA, I-SB, I-SD, I-DM, V-AA, V-RT, V-ST, O-IM, O-EM, O-OM | Control states (automated) + targeted manual answers |

### A.2 Practice-by-practice mapping

Key: **Auto** = share of the practice that can be evidenced automatically (H / M / L). **Fresh** = default evidence freshness. Control IDs link to the [catalogue](control-catalogue.md).

#### Governance

| Practice | Intent (paraphrase) | L1 / L2 / L3 expectation (paraphrase) | Controls | Auto | Evidence & freshness | Assessment method | Exceptions | Improvement actions |
|---|---|---|---|---|---|---|---|---|
| **Strategy & Metrics** | Set a security strategy for software and measure progress | L1 identify drivers and risk appetite · L2 publish a strategy with KPIs · L3 align with business and improve from metrics | – (programme-level) | L | Charter, KPI catalogue, quarterly report pack. 12 months. | Annual interview by Security Governance (M2). **The platform itself is the primary L2/L3 evidence** (metrics exist and are reviewed). | n/a | Adopt the KPI/KRI catalogue. Quarterly leadership review. |
| **Policy & Compliance** | Define policies and standards; manage compliance | L1 policies and standards exist · L2 standards turned into testable checks · L3 adherence measured | ASC-BLD-08, ASC-VUL-03 | M | The control catalogue *is* the testable form of the standards (L2). Control-state reporting is adherence measurement (L3). 12 months. | Interview + platform metrics | n/a | Publish the standards set (docs/standards). Map compliance obligations in `application.yaml`. |
| **Education & Guidance** | Train and enable people; build culture | L1 awareness training · L2 role-based training, champions · L3 in-house guidance, community | ASC-GOV-03, ASC-GOV-04 | M | LMS completion (time_bound 365d), champion roster | Automated coverage + interview for culture items | Per team, max 90 days | Champions programme. Role-based courses. |

#### Design

| Practice | Intent | L1 / L2 / L3 | Controls | Auto | Evidence & freshness | Assessment method | Exceptions | Improvement actions |
|---|---|---|---|---|---|---|---|---|
| **Threat Assessment** | Understand application risk and threats | A: L1 basic risk profile · L2 classification of all apps · L3 periodic review. B: L1 ad-hoc threat modelling · L2 standard method · L3 continuous improvement of models | ASC-GOV-01, -02, ASC-TM-01..03 | M | Classification record (event-bound), threat model files (commit-bound), review record (event-bound, ceiling 365d) | Automated structure + manual review (M2 for T1/T2) | Tier 3/4 only | Threat-model kit. AppSec facilitation for Tier 1. |
| **Security Requirements** | Specify security requirements for software and suppliers | A: L1 requirements identified · L2 structured framework (ASVS) · L3 requirements library, enforced. B: L1 supplier evaluation · L2 contractual requirements · L3 supplier performance tracked | ASC-REQ-01..03 | M | asvs.yaml (C1), requirement verification derived from evidence | Automated + manual supplier assurance | Per requirement | ASVS profile at onboarding. Requirement-tagged tests. |
| **Secure Architecture** | Build security into design and technology choices | A: L1 security principles applied · L2 shared security services / reference architectures · L3 architectures enforced. B: L1 technology inventory · L2 approved technology list · L3 enforced | ASC-ARC-02 (B), A via ASC-ARC-01 review | L (A) / H (B) | SBOM/EOL data, architecture review records | Stream B automated from SBOM. Stream A by architecture review + interview. | Migration plans | Publish reference architectures (auth via Entra, secrets via Key Vault). Approved-technology list. |

#### Implementation

| Practice | Intent | L1 / L2 / L3 | Controls | Auto | Evidence & freshness | Assessment method | Exceptions | Improvement actions |
|---|---|---|---|---|---|---|---|---|
| **Secure Build** | Repeatable, secured build with dependency management | A: L1 defined build process · L2 automated pipeline with security checks · L3 security checks enforced / integrity. B: L1 dependency records (SBOM) · L2 dependencies assessed for risk · L3 dependency risk handled by policy | ASC-SRC-01/02/05/06, ASC-BLD-01..09 | **H** | Scan evidence (commit/artifact bound), ruleset (continuous), provenance | Fully automated | Per control limits | Reusable workflows. Required checks. Provenance. |
| **Secure Deployment** | Secure, verified deployment and secret handling | A: L1 formal deployment process · L2 automated deployment with verification · L3 integrity verified at deploy. B: L1 secrets kept out of code · L2 secrets injected from a vault · L3 secret lifecycle managed | ASC-DEP-01..04, ASC-SRC-03/04 | **H** | Environments API, deploy records, IaC scans, secret-scanning API | Automated | Per control | OIDC everywhere. Environment protection. Attestation verification. |
| **Defect Management** | Track, prioritise and learn from security defects | A: L1 defects tracked · L2 rated with SLAs · L3 SLAs enforced. B: L1 basic metrics · L2 metrics drive improvement · L3 feedback into the SDLC | ASC-VUL-01..04 | **H** (A) / M (B) | Finding projection, SLA clocks (continuous), RCA records (120d) | Automated + periodic process record | Exceptions governed | Risk engine. Jira integration. Recurring-CWE reports. |

#### Verification

| Practice | Intent | L1 / L2 / L3 | Controls | Auto | Evidence & freshness | Assessment method | Exceptions | Improvement actions |
|---|---|---|---|---|---|---|---|---|
| **Architecture Assessment** | Validate the architecture against security needs | A: L1 architecture reviewed ad hoc · L2 validated against requirements and threats · L3 review effectiveness improved. B: L1 mitigations identified · L2 mitigations tracked · L3 feedback into reference architectures | ASC-ARC-01, ASC-ARC-03, ASC-TM-03 | L | Review records (event-bound, ceiling 730d), findings | Manual (M2) with automated tracking | Tier 3/4 | Review service with an SLA. Findings tracked in the platform. |
| **Requirements-driven Testing** | Test that security requirements and abuse cases hold | A: L1 controls tested · L2 tests derived from requirements · L3 regression suite. B: L1 misuse testing · L2 abuse cases from threat models · L3 advanced (e.g. DoS, business logic) | ASC-REQ-02, ASC-TST-02/04/05 | M–H | JUnit with ASVS/threat IDs (commit-bound) | Automated | Per requirement | Test tagging convention. Test-evidence workflow. |
| **Security Testing** | Automated and expert security testing | A: L1 automated tools run · L2 tools tuned to the app · L3 integrated in the pipeline at scale. B: L1 manual review of high-risk components · L2 penetration testing · L3 integrated into development | ASC-BLD-01, ASC-TST-01/02/03 | H (A) / L (B) | SAST/DAST/API evidence, pen-test records (365d) | Automated (A), manual (B) | Per control | DAST/API workflows. Pen-test scheduling. |

#### Operations

| Practice | Intent | L1 / L2 / L3 | Controls | Auto | Evidence & freshness | Assessment method | Exceptions | Improvement actions |
|---|---|---|---|---|---|---|---|---|
| **Incident Management** | Detect and respond to security incidents | A: L1 best-effort detection · L2 defined detection with logging · L3 improved detection. B: L1 named contacts and process · L2 formal IR process · L3 dedicated, exercised capability | ASC-OPS-01, ASC-OPS-02, ASC-GOV-05 | M | SIEM log-source health (24h), runbook + exercise record (365d) | Automated (A) + manual (B) | Tier 2+ | Logging standard. App runbook template. SOC integration. |
| **Environment Management** | Harden and patch the runtime environment | A: L1 best-effort hardening · L2 consistent baselines · L3 conformity monitored. B: L1 best-effort patching · L2 formal patch process · L3 patch SLAs monitored | ASC-BLD-04, ASC-OPS-03, ASC-OPS-04, ASC-ARC-02 | **H** | Cloud posture (24h), deploy + image age, IaC scans | Automated | Compensating controls | Defender/Security Hub mapping. Scheduled image rebuilds. |
| **Operational Management** | Protect data and manage system lifecycle | A: L1 data inventoried · L2 data protection policy applied · L3 automated. B: L1 unused systems identified · L2 decommissioning process · L3 legacy proactively managed | ASC-OPS-05, ASC-OPS-06 | M | Cloud inventory vs declared stores. Lifecycle status. | Automated (once cloud mapping is mature) + interview | Rare | Data-store declaration. Decommissioning runbook. |

### A.3 Maturity calculation

**Step 1: answer per (scope, stream, level).** For each SAMM assessment question (one per stream per level in the official model), the platform derives an answer from the official answer scale. The SAMM Toolbox uses ordinal options worth 0 / 0.25 / 0.5 / 1; **verify against the imported model version**.

```
automated_fraction(stream, level) =
    Σ_c weight(state_c) / count(mandatory mapped controls applicable to the scope)
    where weight: SATISFIED=1, PARTIAL=pro-rata, everything else=0
    (EXCEPTED counts 0: an exception is a risk decision, not maturity;
     NOT_APPLICABLE is removed from the denominator)

automated_answer = band(automated_fraction) onto the official ordinal options, e.g. for the
                   Toolbox-style scale "No / some / at least half / most or all" (0 / 0.25 / 0.5 / 1):
                   0 → 0 · >0 → 0.25 · ≥0.5 → 0.5 · ≥0.8 → 1   (band thresholds are configuration)

if the activity has mapped controls AND a manual answer:
    answer = min(manual_answer, automated_answer + 0.25)     # manual claims cannot exceed what evidence shows,
                                                             # but may add a little for unevidenced nuance
elif only mapped controls:  answer = automated_answer        # provenance: AUTOMATED
elif only manual answer:    answer = manual_answer           # provenance: MANUAL (flagged in UI)
else:                       answer = 0, provenance: UNASSESSED
```

**Step 2: aggregate.** This follows the SAMM Toolbox convention, to be confirmed at import:
- stream score = Σ level answers (0–3)
- practice score = mean of its two stream scores (0–3)
- business-function score = mean of its practice scores
- overall = mean of business functions

**Step 3: report with provenance.** Every score is displayed with its **evidence mix** (% of answers from automated evidence, from M2, from M1, and unassessed) and is drillable to the control states and evidence IDs behind it.

**Organisation and directorate roll-up.** Means hide distribution, so roll-ups show:
- the **distribution** (box plot) of app practice scores per directorate;
- the **% of Tier 1/2 apps meeting their tier's target profile**, which is the headline maturity KPI;
- organisation-level Governance practice scores from the organisational assessment.

A single organisation-wide "SAMM number" is available only in the executive view, always next to its distribution and evidence mix.

**Targets (PROPOSED).** The target maturity profile per tier is set by governance, e.g. Tier 1: Secure Build ≥ 2.5, Secure Deployment ≥ 2.0, Defect Management ≥ 2.0, Security Testing ≥ 2.0, Threat Assessment ≥ 2.0. Targets live in configuration next to the classification model.

**Snapshots.** Monthly immutable snapshots (`maturity_snapshots`) support trend reporting. A change to the catalogue or the methodology is recorded with the snapshot, so a jump caused by a methodology change is not mistaken for improvement.

### A.4 Assessment cadence

| Assessment | Who | When | Evidence level |
|---|---|---|---|
| Automated control evaluation | Platform | Continuous | C1–C3 |
| Application SAMM manual questions (non-automatable activities only) | Champion + AppSec | Annually (Tier 1/2). Sampled for Tier 3. | M1 (T2/T3), M2 (T1) |
| Organisation SAMM (Governance) | Security Governance + external reviewer optional | Annually | M2 |
| Calibration audit | AppSec | Quarterly: sample 5% of automated SATISFIED states and verify manually | Feeds evaluator quality metrics |

## Part B: OWASP ASVS (operational, not a checklist)

### B.1 Requirement catalogue

- **Source:** the official ASVS 5.0 release artefacts (machine-readable export), imported to `framework_requirements` with the version pinned. **Not hand-transcribed.** Backlog: E12-F01.
- **Chapters (5.0):** V1 Encoding & Sanitization · V2 Validation & Business Logic · V3 Web Frontend Security · V4 API & Web Service · V5 File Handling · V6 Authentication · V7 Session Management · V8 Authorization · V9 Self-contained Tokens · V10 OAuth & OIDC · V11 Cryptography · V12 Secure Communication · V13 Configuration · V14 Data Protection · V15 Secure Coding & Architecture · V16 Security Logging & Error Handling · V17 WebRTC. Verify against the release at import.

### B.2 Tier → level

| Tier | ASVS target (PROPOSED) |
|---|---|
| 1 Critical | L3 |
| 2 High | L2 |
| 3 Standard | L1 in full + L2 requirements that have an automated verification method |
| 4 Low | L1 |

### B.3 Applicability model

A requirement applies when (a) its level ≤ the target and (b) its **capability tags** match the application profile in `.security/asvs.yaml`:

| Capability flag (asvs.yaml) | Primarily scopes |
|---|---|
| `web_frontend` | V3 |
| `api` | V4 |
| `file_handling` | V5 |
| `authentication: local \| federated \| none` | V6 (local auth requirements drop out when fully federated to Entra; federation requirements remain) |
| `sessions` | V7 |
| `self_contained_tokens` | V9 |
| `oauth_oidc: client \| resource_server \| authorization_server` | V10 subsections |
| `webrtc` | V17 |

Requirement-to-tag mapping is maintained by AppSec in `catalogue/frameworks/asvs-applicability.yaml` (E12-F02). Teams can mark further requirements N/A only with justification; AppSec approves N/A for Tier 1.

### B.4 Verification methods and evidence

| Method | How it becomes evidence | Can it mark a requirement VERIFIED? |
|---|---|---|
| **Automated test** | JUnit `<property name="asvs" value="v5.0.0-x.y.z"/>` collected by `test-evidence` workflow | **Yes**, if passing on the current default branch |
| **Configuration check** | Evaluator inspects config (headers via DAST, TLS via scan, IaC policy) | **Yes**, for config-type requirements |
| **Scanner rule (SAST/DAST)** | Scanner rule → CWE → ASVS mapping | **No.** Absence of findings is *supporting* evidence (`SCANNED_NO_ISSUES`). Presence of a finding marks the requirement `FAILED`. |
| **Manual review / pen test** | Review record lists requirement IDs checked (M2) | **Yes** (time-bound) |
| **Design review / threat model** | Mitigation references in `mitigations.yaml` | Supporting only, unless reviewed (M2) |

Requirement status per app: `VERIFIED` · `SCANNED_NO_ISSUES` · `FAILED` · `UNVERIFIED` · `EXCEPTED` · `NOT_APPLICABLE`. The ASVS view groups by chapter and shows which method backs each status. A requirement cannot be marked verified by hand without a review record.

### B.5 Worked example (Tier 1 citizen-facing API)

```
classification: FR-1 (internet + special-category data) → Tier 1 → ASVS target L3
asvs.yaml: api, authentication: federated, oauth_oidc: resource_server, self_contained_tokens, file_handling
  → ~N applicable requirements (exact count from import)
evidence:
  test-evidence workflow: 64 tests tagged across V4/V8/V9/V10 → 51 requirements VERIFIED
  DAST (authenticated) + API scan: header/TLS/config requirements VERIFIED, 3 FAILED (findings raised, P2)
  CodeQL: no injection findings → V1 requirements SCANNED_NO_ISSUES (not VERIFIED)
  annual pen test (M2): 40 requirements VERIFIED until expiry
control ASC-REQ-02: verified% = VERIFIED / applicable → compared to the 80% threshold for Tier 1
SAMM: feeds D-SR-A L2 and V-RT-A L1–L3 via ASC-REQ-02 / ASC-TST-05
```

### B.6 ASVS exceptions

An exception against an ASVS requirement uses the standard exception workflow ([ADR-021](../../adr/ADR-021-security-exceptions.md)) with `target_type = asvs_requirement`. Typical case: a legacy component cannot meet a V11 cryptography requirement before migration. The exception expires, and expiry reopens the requirement as `FAILED` with a finding.
