# Business Case: Application Security Assurance Programme

| | |
|---|---|
| Version | 0.1 OUTLINE. Cost figures to be completed in Phase 0 (WP0.6) with Finance. **No cost figures in this draft are quotes.** |
| Status | Template. Approved by the sponsor and finance. |
| Parent | [Programme Charter](programme-charter.md) |

## 1. Strategic case (summary)

The organisation cannot evidence the security of its applications. Tools exist but are disconnected from ownership, criticality and controls. See the [charter section 2](programme-charter.md#2-problem-statement) and [current state](../../governance/target-state-assessment.md). The programme supports the [AppSec strategy](../../governance/appsec-strategy.md) objectives SO1–SO7.

## 2. Options appraisal

| Option | Description | Benefits | Costs / risks | Assessment |
|---|---|---|---|---|
| **0. Do nothing** | Continue with GHAS + pilot DT/DD | No new spend | No inventory, evidence or maturity. Severity-driven triage. Ungoverned risk acceptance. Scaffold weaknesses (CS-1–7) persist. | Fails the objectives |
| **1. Minimum: deploy DT/DD only** | Finish the scaffold, onboard more repos | SCA visibility, finding triage | Still no application context, controls, evidence or maturity. Repo-held keys sprawl (CS-1). | Partial. Necessary but insufficient. |
| **2. Buy a commercial ASPM** | Aggregation and prioritisation product | Faster start for aggregation | Licence scales with repos/devs. Weaker evidence immutability and SAMM/ASVS semantics (to verify). Data leaves the tenant. Integration still needed. | **Evaluate in Phase 0** against the must-have requirements |
| **3. Build the assurance layer on existing tools (recommended, subject to option 2 check)** | This design | Full fit (evidence model, SoD, residency, SAMM/ASVS). Reuses licensed and scaffolded tools. No per-repo licences. | Build and run cost. Delivery risk (R-02). | Preferred if option 2 fails must-haves or costs more over 3 years |

**Must-have requirements for any option:** verifiable evidence with confidence levels · immutability/tamper evidence · SoD-enforced exceptions with expiry · contextual risk with explainability · CVE impact across SBOMs with honest "unknown" · UK data residency · Entra SSO/RBAC with business unit scoping · API access.

## 3. Cost model (to be priced)

### 3.1 People (largest cost)

| Role | FTE Phase 0–1 | FTE Phase 2–9 | FTE steady state |
|---|---|---|---|
| Platform engineers | 2 | 4 | 3 |
| Frontend engineer | 0 | 1 | 0.5 |
| Product owner | 1 | 1 | 1 |
| AppSec engineers | 1 | 2 | ~1 per 40 Tier 1/2 apps |
| Governance analyst | 0.5 | 0.5 | 1 |
| AppSec lead (share) | 0.5 | 0.5 | 0.3 |
| Champions (distributed) | — | ~10% per pilot team | ~10% per team |

### 3.2 Azure run costs: drivers and initial sizing

| Component | Initial sizing assumption | Cost driver |
|---|---|---|
| Container Apps (web, hook, worker) | Workload-profile environment. ~6 vCPU steady, bursting for scans. | vCPU/GB-seconds, dedicated profile if used |
| PostgreSQL Flexible Server | General Purpose 4 vCores, zone-redundant HA, 512 GB, geo-redundant backup | vCore + HA doubling + storage + backup |
| Blob Storage (WORM, GRS) | ~1 TB/year raw evidence, tiered cool/archive | GB-month by tier, transactions, GRS |
| Key Vault Premium | HSM-backed keys for the GitHub App | Operations + HSM key |
| Log Analytics / App Insights | ~5–10 GB/day telemetry | Ingestion GB, retention |
| Sentinel | Curated events (low volume) + checkpoints | Ingestion GB |
| Networking | NAT Gateway / firewall rules (hub firewall may be shared), private endpoints ×5, private DNS | Endpoints/hour, data processed |
| ACR Premium (geo-replicated) | Platform images | Replicas |
| DefectDojo + Dependency-Track (existing scaffold, resized) | DT apiserver ≥ 4 GB heap (dedicated profile), separate PG logins | As above |
| Pen test (annual) | External provider | Day rate × days |

Action (Phase 0): produce 3-year TCO for options 2 and 3 using the Azure pricing calculator and vendor quotes. Include people costs in both (ASPM still needs integration, governance and AppSec effort).

## 4. Benefits

| Benefit | Type | Quantification method |
|---|---|---|
| Reduced exposure to actively exploited vulnerabilities | Risk reduction | KEV-exposure count × days (baseline vs month 12) |
| Less effort on low-risk "criticals" | Efficiency | Remediation hours by contextual priority (pilot time-tracking sample) |
| Faster CVE response | Risk reduction | Time to list affected apps (exercise baseline vs platform) |
| Audit preparation time | Efficiency | Hours to evidence controls (last audit vs platform) |
| Avoided per-repo licences | Cost avoidance | Option 2 licence quote minus option 3 run cost |
| Defensible maturity reporting | Governance | % of maturity answers backed by C2+/M2 evidence |

Benefits realisation ownership and review: [charter section 21](programme-charter.md#21-benefits-realisation).

## 5. Commercial and procurement

No procurement for option 3 beyond the Azure consumption and pen-test services. Option 2 would need a procurement exercise (data processing terms, residency, exit plan).

## 6. Management case

Governance, PID, risks and roadmap: [charter](programme-charter.md), [PID](project-initiation-document.md), [risk register](../risk-register/risk-register.md), [roadmap](../roadmap/roadmap.md).
