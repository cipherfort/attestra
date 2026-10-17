# Governance Model

| | |
|---|---|
| Status | DESIGNED: decision rights and thresholds REQUIRE HUMAN APPROVAL (CISO) |
| Related | [Target operating model](target-operating-model.md), [RACI](../programme/raci/raci.md), [ADR-021 Exceptions](../../adr/ADR-021-security-exceptions.md) |

## 1. Structure

```
                     ┌──────────────────────────────┐
                     │  CISO / Security Leadership  │  risk appetite, policy, P1 risk acceptance
                     └──────────────┬───────────────┘
                                    │ quarterly
                     ┌──────────────▼───────────────┐
                     │  AppSec Governance Board     │  catalogue, risk model, targets, escalations
                     │  chair: Head of AppSec       │  members: directorate security leads, platform PO,
                     └──────────────┬───────────────┘  cloud security, SOC lead, governance analyst
                                    │ monthly
          ┌─────────────────────────┼──────────────────────────┐
┌─────────▼──────────┐  ┌───────────▼───────────┐  ┌────────────▼──────────┐
│ Security Engineering│  │ Platform Security /   │  │ Central Security      │
│ (AppSec engineers)  │  │ AppSec Platform team  │  │ Governance (GRC)      │
│ reviews, triage,    │  │ build & run platform, │  │ exceptions workflow,  │
│ threat modelling    │  │ security-workflows    │  │ reporting, audit      │
└─────────┬──────────┘  └───────────┬───────────┘  └────────────┬──────────┘
          └─────────────────────────┼──────────────────────────┘
                     ┌──────────────▼───────────────┐
                     │ Directorates → Product teams │  own apps, controls, remediation
                     └──────────────┬───────────────┘
                     ┌──────────────▼───────────────┐
                     │ Security Champions           │  first-line security in each team
                     └──────────────────────────────┘
```

## 2. Policy hierarchy

| Layer | Owner | Changed by | Example |
|---|---|---|---|
| **Policy** | CISO | Policy board | "All applications shall meet the controls required for their tier." |
| **Standards** | Head of AppSec | Governance Board | Secure SDLC Standard, Vulnerability Management Standard (Stage 3 docs) |
| **Control catalogue** (machine-readable) | Head of AppSec (catalogue owner) | PR + Governance Board for mandatory changes | `catalogue/controls/controls.yaml` |
| **Configuration** (risk model, tiers, SLAs) | Head of AppSec | PR + Board approval | `config/*.yaml` |
| **Guidance** | AppSec engineers | PR | How-tos, threat-model kit |

Standards state *what* and *why*. The catalogue states *how it is tested*. A standard that cannot be traced to catalogue controls is reviewed for testability.

## 3. Decision rights

| Decision | Proposes | Decides | Consulted | Recorded in |
|---|---|---|---|---|
| Add or tighten a **mandatory** control | AppSec / Platform | Governance Board | Directorate leads | Catalogue PR + Board minutes |
| Add a recommended control or change a mapping | AppSec | Head of AppSec | Platform PO | Catalogue PR |
| Change risk model weights, bands or SLAs | AppSec | Governance Board (CISO for SLA changes) | SOC, directorates | Config PR + minutes |
| Change classification model | AppSec | Governance Board | Info governance, DPO | Config PR |
| Tier override (downgrade) | App owner | Head of AppSec (Tier 1/2 → lower); AppSec engineer (3 → 4) | Directorate lead | Platform classification ledger |
| Enable a merge **gate** for a tier | Platform PO | Governance Board | Champions, engineering leads | Board minutes + workflow release |
| Change a default **tool** in security-workflows | Platform team | Head of AppSec | AppSec, champions | ADR + release notes |
| Grant org-wide data access role | Requester | Head of AppSec (+ PIM approval) | Governance analyst | Entra PIM + audit |
| Publish organisational maturity externally (outside security leadership) | Governance analyst | CISO | Head of AppSec | Report register |

## 4. Risk acceptance (exception approval thresholds)

Approver authority depends on **residual priority** and **tier**. These values are PROPOSED.

| Residual priority ↓ / Tier → | Tier 1 | Tier 2 | Tier 3 | Tier 4 | Max duration |
|---|---|---|---|---|---|
| **P1** | CISO | CISO | Head of AppSec | Head of AppSec | 30 days, 1 renewal |
| **P2** | Head of AppSec | Head of AppSec | Directorate Security Lead | Directorate Security Lead | 90 days |
| **P3** | Head of AppSec | Directorate Security Lead | Directorate Security Lead | AppSec engineer | 180 days |
| **P4** | Directorate Security Lead | AppSec engineer | AppSec engineer | AppSec engineer | 365 days |
| Control gap (mandatory control) | as P2 row | as P2 row | as P3 row | as P4 row | Per control `exception.max_days` |

Rules enforced by the platform:
- The approver cannot be the requester, the app's technical owner or a member of the owning team.
- The **business owner co-signs** every Tier 1/2 exception. They own the business risk; security owns the advice.
- Renewal requires fresh approval. More than 2 renewals escalates to the next approver level automatically.
- On expiry, the exception becomes a finding (`exception_expired`) with the original priority and a **new, shorter SLA** (half the normal SLA). The owner and approver are notified.
- Some controls allow **no exceptions**: active exposed secrets, malicious packages, application registration, classification, governed exceptions themselves.

## 5. Escalation

| Trigger | Day 0 | +7 days | +30 days |
|---|---|---|---|
| P1 SLA breach | Tech owner + champion + Head of AppSec. SOC event ([ADR-020](../../adr/ADR-020-siem-integration.md)). | Directorate lead + CISO | Governance Board, risk register entry |
| P2 SLA breach | Tech owner + champion | Directorate Security Lead | Governance Board |
| Mandatory control gap (Tier 1/2) past grace period | Champion + tech owner | Directorate Security Lead | Governance Board |
| Expired exception | Owner + approver | Next approver level | Governance Board |
| Evidence integrity failure (hash chain / attestation anomaly) | Platform on-call + Head of AppSec (P1 platform incident) | | |

Escalations are generated from SLA clocks, not by hand. The weekly digest per directorate lists everything at +7 days and beyond.

## 6. Forums and cadence

| Forum | Cadence | Chair | Inputs (from the platform) | Outputs |
|---|---|---|---|---|
| AppSec triage | Weekly | Lead AppSec engineer | New P1/P2, FP requests, escalations | Decisions, assignments |
| Champions community | Fortnightly | Champions lead | Recurring CWE trends, new controls, tool changes | Feedback, training needs |
| Directorate security review | Monthly | Directorate Security Lead | Directorate scorecard, SLA, exceptions due | Actions, escalations |
| **AppSec Governance Board** | Monthly | Head of AppSec | Org scorecard, catalogue/config PRs, escalations, KRIs | Approvals, risk decisions |
| Security leadership review | Quarterly | CISO | Maturity trend, KPI/KRI pack, top risks, programme status | Direction, risk acceptance |
| Catalogue and methodology review | Annually | Head of AppSec | Control effectiveness, calibration audits, framework updates | Catalogue major version |
| Organisational SAMM assessment | Annually | Governance analyst | Platform maturity + interviews | Org maturity baseline |

## 7. Reporting

| Audience | Content | Frequency | Channel |
|---|---|---|---|
| Engineers / champions | Their findings, control gaps, what to fix next | Real time + weekly digest | Platform UI, Jira, Teams |
| App owners | App scorecard, exceptions expiring, SLA | Monthly digest | UI, email |
| Directorate leads | Directorate distribution, SLA, gaps, maturity vs target | Monthly | UI + PDF pack |
| Security leadership | Org maturity trend + distribution, KRIs, top risks, programme progress | Monthly/quarterly | UI exec view + pack |
| Executives | Coverage, % Tier 1 meeting target, KEV exposure, trend | Quarterly | One-page pack |
| Audit | Evidence chains on request, control-state history | On demand | Auditor role (read-only) |
