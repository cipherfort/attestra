# Programme Charter: Application Security Assurance Programme

| | |
|---|---|
| Version | 0.1 DRAFT for leadership review |
| Date | 2026-10-07 |
| Sponsor | CISO (**to confirm**) |
| Programme owner | Head of Application Security (**to confirm**) |
| Status | **REQUIRES HUMAN APPROVAL.** No commitment is made until signed off at the Security Leadership review. |

---

## 1. Executive summary

We build and run a large, growing estate of applications on GitHub, Azure and AWS. **We cannot currently show, with evidence, which of them are built and run securely.** We have good tools (GitHub Advanced Security, Defender, Sentinel, and a scaffolded Dependency-Track/DefectDojo), but they do not know which application a finding belongs to, who owns it, how critical it is, or which security controls it should have.

This programme establishes an **evidence-driven application security capability**. At its core is an internal platform that:

1. keeps an authoritative **register of applications**, owners and risk tiers;
2. defines **testable security controls** per tier, mapped to OWASP SAMM, OWASP ASVS and NIST SSDF;
3. gives teams a **paved-road security pipeline** that runs the tests and produces **verifiable, tamper-evident evidence**;
4. **prioritises vulnerabilities by real risk** (exploitation in the wild, exposure, data, criticality), not raw severity;
5. tracks remediation through Jira and **closes issues only when a re-test proves the fix**;
6. derives **SAMM maturity from evidence** rather than questionnaires, with the evidence behind each number visible.

**The ask:** approve Phase 0 (discovery and governance, 6 weeks) and Phase 1 (foundation), resource a core team of ~6, and confirm the decisions listed in section 19.

## 2. Problem statement

- **No application inventory.** Findings attach to repositories, not services, owners or business impact.
- **No defined controls.** "We do SAST" has no definition of scope, frequency, pass criteria or proof.
- **No retained evidence.** Pipeline results expire after 30 days. Nothing is attributable or tamper-evident.
- **Severity-driven triage.** Teams face long "critical" lists that do not reflect exploitability or exposure.
- **Ungoverned risk acceptance.** "Risk accepted" in a tool has no owner, approver or expiry.
- **Maturity by self-assessment.** No defensible answer to "how mature is our application security?"

Detailed current state, including security observations on the existing scaffold: [01-problem-definition](../../../docs/architecture/01-problem-definition.md).

## 3. Opportunity

- **Use what we already pay for.** GHAS Enterprise is licensed org-wide. Dependency-Track and DefectDojo are scaffolded. The programme connects them instead of buying overlapping tools.
- **Shift effort from triage to fixing** by focusing teams on the small fraction of vulnerabilities that are exploited in the wild and reachable.
- **Answer "are we affected?" in minutes** during the next Log4Shell-class event, from SBOM inventory across every application.
- **Audit-ready by construction:** every claim traceable to evidence.

## 4. Objectives (SMART; targets PROPOSED for confirmation in Phase 0)

| # | Objective | Measure | Target |
|---|---|---|---|
| O1 | Know our estate | % production apps registered with owners and tier | 100% Tier 1/2 by month 9. ≥ 90% all by month 15. |
| O2 | Continuous security testing | % Tier 1/2 repos with current C2+ evidence for SAST, SCA, secrets, SBOM | ≥ 90% by month 12 |
| O3 | Risk-based remediation | P1 SLA compliance (7 days, verified by re-scan) | ≥ 95% by month 12 |
| O4 | Fast CVE response | Time to list affected apps for a new critical CVE | < 15 minutes from platform query |
| O5 | Evidence-backed maturity | % of Tier 1 apps meeting their SAMM target profile | Baseline at month 6. +30 pts by month 18. |
| O6 | Governed risk | Exceptions with owner, approver and expiry | 100% from go-live. 0 expired exceptions without a finding. |
| O7 | Secure platform | Platform onboarded to itself, independent pen test passed | Before pilot exit |

## 5. Scope

**In scope:** applications and services developed or maintained by the organisation in GitHub; their pipelines, dependencies, container images and IaC; their Azure/AWS hosting scopes (posture findings); the control catalogue, evidence, risk, exceptions, maturity and reporting; the Security Champions programme; integration with Jira and Sentinel (curated events); the platform itself.

## 6. Out of scope

Commercial off-the-shelf software without source access (registry entry only, supplier assurance via ASC-REQ-03) · runtime protection (WAF/RASP) · endpoint and network security · non-software GRC · replacement of GHAS, Dependency-Track, DefectDojo, Defender or Sentinel · individual developer performance measurement (explicitly prohibited use).

## 7. Stakeholders

| Stakeholder | Interest | Engagement |
|---|---|---|
| CISO | Organisational risk, assurance, regulatory posture | Sponsor. Quarterly review. |
| CTO / Heads of Engineering | Delivery speed, developer experience | Steering. Gating decisions. |
| Business unit leaders | Their services' risk and compliance | Monthly business unit review |
| Engineering teams and champions | Actionable, low-noise work | Pilot co-design. Champions community. |
| Cloud Security / Platform Engineering | Cloud integrations, GitHub org settings | Working group |
| SOC | High-value, low-noise events | Event catalogue sign-off |
| Information Governance / DPO | Personal data in the platform | DPIA |
| Internal Audit | Evidence quality | Early review of the evidence model |
| Procurement / Legal | OSS licences, supplier assurance | Licence policy approval |

## 8. Governance

Sponsor: CISO. Owner: AppSec lead. Decision forum: the **AppSec Governance Board** (monthly), escalating to the **Security Leadership Review** (quarterly). Decision rights, risk-acceptance thresholds and escalation: [governance model](../../governance/governance-model.md).

## 9. Assumptions

GitHub Enterprise Cloud with GHAS covers in-scope orgs · Entra ID is the IdP · Azure (UK South) hosts the platform · Jira is available with API access · artifact attestations are available for private repos · 100–500 applications, 300–2,000 repos · a data-classification scheme exists. Each has a validation step in Phase 0 ([problem definition section 7](../../../docs/architecture/01-problem-definition.md#7-assumptions-to-be-validated-in-phase-0)).

## 10. Constraints

Existing licences and tools are reused before buying new ones · data stays in the organisation's Azure tenant · the platform must not block delivery if it is unavailable · no individual performance metrics · private networking for sensitive data · team size as resourced (section 16).

## 11. Key risks (top 8; full register: [risk register](../risk-register/risk-register.md))

| ID | Risk | Rating | Mitigation |
|---|---|---|---|
| R-01 | Engineering teams see the programme as overhead and resist onboarding | High | Paved road (one file), pilot co-design, observe-first, champions, visible noise reduction |
| R-02 | Insufficient platform team capacity → slipping roadmap | High | Phase-gated scope. Build vs buy check at Phase 0 exit. |
| R-03 | Ownership data is wrong or missing | High | Owner resolution checks. Departed-owner detection. Business unit accountability. |
| R-04 | Evidence model too strict early → "everything red" demoralises teams | Medium | Observe mode for new controls, grace periods, tier-phased targets |
| R-05 | GitHub App / platform compromise exposes the organisation's vulnerability map | Medium (high impact) | Read-only App, private networking, threat model, independent pen test |
| R-06 | Key external configurations delayed (org rulesets, Entra, AWS federation, Jira) | Medium | Raised in Phase 0 with named owners and dates |
| R-07 | Maturity scores misused for performance management or league tables | Medium | Governance rule, team-level metrics only, provenance shown |
| R-08 | DefectDojo/Dependency-Track remain undeployed or fragile | Medium | Deploy hardened in Phase 1–2 as dependencies, with the hardening items from the current-state review |

## 12. Dependencies

The project creates and owns every technical integration ([ADR-031](../../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md)): GitHub organization and App, Entra apps and groups, network, Sentinel, Dependency-Track/DefectDojo, cloud reader roles, Jira. The remaining dependencies are **accounts and approvals**: the programme sponsor (accounts, GitHub plan D-018), the SOC lead (event list), DPO (DPIA), Legal (licence policy), Records management (retention, WORM lock D-016).

## 13. Success criteria

1. Pilot (3–5 apps) demonstrates the full **control → test → evidence → risk → ticket → fix → re-test → maturity** loop with real repositories ([pilot criteria](../roadmap/roadmap.md#pilot-phase-9)).
2. Leadership receives a maturity report in which **every number is drillable to evidence**.
3. Teams report the security work is **clearer and lower-noise** than before (pilot survey ≥ 70% positive).
4. Independent pen test of the platform finds no high/critical issues at go-live.

## 14. KPIs

| KPI | Definition | Direction |
|---|---|---|
| Registry coverage | Registered prod apps ÷ discovered prod apps (from deployments/cloud) | ↑ |
| Control coverage | Mandatory controls satisfied at required confidence ÷ applicable mandatory controls (Tier 1/2) | ↑ |
| Evidence freshness | Mandatory-control evidence current ÷ total | ↑ |
| Automated evidence share | Controls satisfied by C2/C3 ÷ satisfied | ↑ |
| MTTR (P1/P2) | Detection → *verified* fix, median and p90 | ↓ |
| SLA compliance | Findings fixed within SLA ÷ due, by priority | ↑ |
| SBOM coverage | Deployed artifacts with current build SBOM | ↑ |
| Threat-model coverage | Tier 1/2 apps with current reviewed threat model | ↑ |
| Tier 1 at target maturity | Tier 1 apps meeting the SAMM target profile | ↑ |
| Champion coverage | Teams with a trained champion | ↑ |

## 15. KRIs (thresholds trigger Board escalation)

| KRI | Threshold (PROPOSED) |
|---|---|
| Open KEV-listed vulnerabilities on internet-facing apps | > 0 for > 7 days |
| P1 findings past SLA | > 0 |
| Expired exceptions | > 0 for > 7 days |
| "Dark" apps (registered production apps with no evidence in 30 days) | > 5% |
| Unregistered repos with production deployments | > 0 for Tier-1-like signals (internet + data) |
| Unattributed cloud findings | > 20% |
| Unmanaged tool suppressions | Rising 3 months in a row |
| Evidence integrity verification failures | > 0 |
| Connector staleness > 2× interval | > 24h |

**Anti-gaming design:** no KPI rewards fewer findings. Detection counts are context, not targets ([TOM section 7](../../governance/target-operating-model.md#7-how-the-tom-avoids-gaming)).

## 16. Resource requirements (indicative, to be refined in the Business Case)

| Role | Phase 0–1 | Phase 2–9 | Steady state |
|---|---|---|---|
| AppSec lead (programme owner) | 0.5 | 0.5 | 0.3 |
| Platform Product Owner | 1 | 1 | 1 |
| Platform engineers (Python, Azure, GitHub) | 2 | 4 | 3 |
| Frontend engineer | 0 | 1 | 0.5 |
| AppSec engineers (reviews, threat models, catalogue) | 1 | 2 | 1 per ~40 Tier 1/2 apps |
| Governance / GRC analyst | 0.5 | 0.5 | 1 |
| Champions | — | ~10% of one engineer per pilot team | ~10% per team |

**Run costs:** Azure Container Apps, PostgreSQL Flexible (zone-redundant HA), Blob (WORM, tiered), Key Vault Premium, Log Analytics/Sentinel ingestion, private networking. The Phase 0 Business Case will cost these with ranges. No new per-repo licences are assumed.

## 17. Deliverables

Stage 1 (this package): problem definition, TOM, architecture, security architecture and threat model, control framework and 48-control catalogue, data model (verified DDL), repository contract, pipeline architecture, evidence model, SAMM/ASVS methodology, governance model, charter, PID, 30 ADRs, risk register, RACI, roadmap, backlog.
Later stages: standards set (40 documents), platform (backend, frontend, workers, IaC), `security-workflows`, integrations, test suites, runbooks, pilot report, rollout plan.

## 18. Roadmap (summary)

| Phase | Months | Outcome |
|---|---|---|
| 0 Discovery and governance | 0–1.5 | Inventory baseline, approvals, external config requests, buy-vs-build check |
| 1 Architecture and foundation | 1–3 | Infra, auth, data model, CI/CD, catalogue loader |
| 2 Application registry | 2–4 | Registry, classification, onboarding |
| 3 Security pipeline | 3–5 | `security-workflows` v1, migration from infra-repo workflows |
| 4 Evidence platform | 3–6 | Ingestion, verification, WORM, freshness, evaluator |
| 5 Vulnerability / SBOM | 4–7 | DD/DT integration, risk engine, CVE query |
| 6 SAMM / ASVS automation | 6–8 | Maturity derivation, ASVS requirement status |
| 7 Dashboard | 5–8 | Role-based views |
| 8 Cloud / SOC / Jira | 6–9 | Integrations |
| 9 Pilot | 7–10 | 3–5 apps end to end |
| 10 Rollout | 10–15 | Waves by tier |
| 11 Optimisation | 15–18+ | Gating, SSVC, VEX, package proxy |

Detail: [roadmap](../roadmap/roadmap.md).

## 19. Decisions requested from leadership

1. Approve Phases 0–1 and the core team.
2. Confirm sponsor, programme owner and Governance Board membership.
3. Approve the **design principles**: evidence over assertion; observe before gate; platform never in the delivery critical path; no individual performance metrics.
4. Mandate registration of production applications (policy statement).
5. Nominate owners for external dependencies (section 12) with dates.

## 20. Operating model, RACI, forums and reporting

Operating model: [target operating model](../../governance/target-operating-model.md). RACI: [RACI](../raci/raci.md). Forums and reporting: [governance model sections 6–7](../../governance/governance-model.md#6-forums-and-cadence).

## 21. Benefits realisation

| Benefit | Measure | Baseline (Phase 0) | Target | Owner | Review |
|---|---|---|---|---|---|
| Faster response to critical CVEs | Time to list affected apps | Measure on a recent CVE exercise | < 15 min | AppSec lead | Each major CVE |
| Less wasted remediation effort | % remediation effort on P1/P2 (contextual) vs tool-critical | Pilot sample | ≥ 60% of effort on P1/P2 | Business unit leads | Quarterly |
| Reduced exposure to exploited vulns | KEV-listed open on internet-facing apps (count × days) | Phase 0 scan | ↓ 80% by month 12 | CISO | Monthly |
| Audit efficiency | Hours to evidence a control for audit | Last audit | ↓ 70% | GOV | Annually |
| Defensible maturity | % maturity answers backed by C2+/M2 evidence | ~0% | ≥ 60% for application practices | AppSec lead | Quarterly |
| Developer experience | Pilot team survey: clarity, noise | Pre-pilot survey | ≥ 70% positive | Platform PO | Pilot exit + 6-monthly |

## 22. Exit criteria (programme → business as usual)

- ≥ 90% of production apps registered. 100% of Tier 1/2 onboarded to the pipeline with current evidence.
- KPIs reported monthly for 6 consecutive months without manual data assembly.
- Platform operated by a named BAU team with on-call, runbooks, a tested DR drill and a passed pen test.
- Governance Board running for 6 months, with the catalogue v1.x approved and reviewed once.
- Remaining roadmap items transferred to the BAU backlog with an owner.
