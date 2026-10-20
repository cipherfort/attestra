# Target Operating Model

| | |
|---|---|
| Status | DESIGNED: requires approval from the Head of Security Engineering and CISO |
| Related | [Governance Model](governance-model.md), [RACI](../programme/raci/raci.md), [Charter](../programme/charter/programme-charter.md) |

## 1. Operating principles

1. **Paved road, not toll gate.** Teams get secure-by-default reusable workflows, templates and guidance. Controls are adopted by *using the road*, not by filling in forms.
2. **Control → Test → Evidence → Risk → Remediation → Re-test.** Every control is defined by how its operation is proven. If the only proof is "someone checks a spreadsheet", we keep looking for an automated test. If none exists, the control is explicitly classed *manual* with a named reviewer and a review cycle.
3. **Detection is never penalised.** A scan that finds vulnerabilities is a control that is *operating*. Teams are measured on coverage, freshness and remediation within SLA, not on raw finding counts. Raw counts reward turning scanners off.
4. **Ownership is explicit.** Every application, control, finding, exception and evidence source has one named accountable owner.
5. **Risk acceptance is a governance decision, not a tool setting.** Only an approved, time-bound exception in the platform accepts risk. Scanner suppressions are tracked, never trusted.
6. **Explainability over scores.** Every derived number (risk priority, control state, maturity) can be expanded down to its inputs and rule version.
7. **Observability first, gating second.** Gates are introduced per control, per tier, after a measured baseline. This matches the existing platform's stance (infra ADR-0001).

## 2. Capability model

```
┌──────────────────────────── Governance ─────────────────────────────┐
│ Policy & standards · Control catalogue ownership · Risk acceptance  │
│ Maturity targets · Reporting · Exception approval                   │
├──────────────────────────── Enablement ─────────────────────────────┤
│ Reusable security workflows · Repo templates · Threat-model kit     │
│ Security Champions · Training · Guidance · Office hours              │
├──────────────────────────── Assurance ──────────────────────────────┤
│ Evidence engine · Control evaluation · Manual assessments           │
│ Architecture review · Pen-test scheduling · SAMM assessment         │
├──────────────────────────── Operations ─────────────────────────────┤
│ Finding triage · Risk engine · Jira workflow · SLA tracking         │
│ CVE response ("who is affected?") · SOC escalation · Platform ops   │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Roles

| Role | Where it sits | Core responsibilities | Indicative FTE (pilot → steady state) |
|---|---|---|---|
| **AppSec lead** | Security Engineering | Owns the programme, control catalogue, maturity targets. Approves Tier 1 exceptions up to a defined risk level. | 1 |
| **AppSec Platform Product Owner** | Security Engineering | Owns the platform roadmap, backlog and onboarding experience. | 1 |
| **AppSec Platform Engineers** | Security Engineering | Build and run the platform, connectors and reusable workflows. | 3 → 4 |
| **Application Security Engineers** | Security Engineering | Threat-model facilitation, architecture review, manual verification, triage escalation, champion support. | 2 → 1 per ~40 Tier 1/2 apps |
| **Security Governance / GRC Analyst** | Central Security Governance | Exception workflow, risk register linkage, reporting packs, audit liaison. | 0.5 → 1 |
| **Business Unit Security Lead** | Each business unit | Accountable for business unit maturity and SLA performance. Approves Tier 3/4 exceptions. | Role, not FTE |
| **Application Owner (business)** | Product / service | Accountable for application risk. Signs off risk acceptance with the security approver. | Role |
| **Technical Owner** | Engineering team | Accountable for remediation and for control implementation in their repos. | Role |
| **Security Champion** | Engineering team | Primary contact. Leads threat modelling with AppSec support. Triages findings within the team. | ~10% of one engineer per team |
| **SOC Analyst** | SOC | Handles the defined subset of AppSec events that need SOC visibility ([ADR-020](../../adr/ADR-020-siem-integration.md)). | Existing |
| **Cloud Security Engineer** | Cloud Security | Owns Defender, Security Hub and Azure Policy integrations, and cloud scope → application mapping. | Existing |

## 4. Engagement model by tier

| | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---|---|---|---|
| Onboarding | AppSec-assisted | AppSec-assisted | Self-service | Self-service |
| Threat model | Facilitated by AppSec, reviewed annually and on architecture change | Champion-led, AppSec-reviewed | Champion-led, lightweight template | Optional |
| Architecture review | Required pre-production and on material change | Required on material change | On request | No |
| ASVS target (proposed) | L3 | L2 | L1 + automatable L2 | L1 |
| Pen test | Annual + on major change | Biennial or on major change | Risk-based | No |
| Manual SAMM assessment | Annual, independent | Annual, champion + AppSec | Automated-only, with sampling | Automated-only |
| Exception approver | AppSec lead (+ CISO above threshold) | AppSec lead | Business Unit Security Lead | Business Unit Security Lead |

The tier boundaries and ASVS levels above are **PROPOSED** and **REQUIRE HUMAN APPROVAL**. The [classification model](../../docs/standards/control-framework.md#3-application-classification-model) is configuration, so they can change without code changes.

## 5. Core processes

| Process | Trigger | Primary automation | Human step |
|---|---|---|---|
| **Application onboarding** | New repo or app discovered | Discovery of repos without `.security/application.yaml`. PR bot opens a templated onboarding PR. | Owner completes classification questions. AppSec confirms the tier for Tier 1/2. |
| **Classification review** | Annually, or when a classification-relevant field changes in `application.yaml` | Change detection on the file and on cloud exposure | Owner re-attests. AppSec approves a tier downgrade. |
| **Continuous control evaluation** | Every evidence event, plus a scheduled sweep | Control evaluator | None, unless the control is manual |
| **Manual assessment** | Due date from freshness policy | Task created in the platform and Jira | Reviewer records the outcome and attaches evidence |
| **Finding triage** | New P1/P2 finding | Risk engine priority, Jira ticket, champion notified | Champion confirms or marks false positive (false positive requires a second reviewer for P1/P2) |
| **Remediation verification** | Fix merged | Re-scan evidence closes the finding. The ticket transitions automatically. | None |
| **Exception** | Team cannot meet a control or SLA | Workflow with risk pre-filled | Approver decision. Expiry is enforced automatically. |
| **CVE response** | High-profile CVE / KEV addition | Component search across all SBOMs, including stale ones | AppSec declares an incident-grade response if needed |
| **Maturity reporting** | Monthly | Snapshot and trend | Narrative from AppSec lead |

## 6. Service levels the programme offers teams

| Service | Target |
|---|---|
| Onboarding PR generated after repo discovery | < 1 business day |
| Threat-model facilitation for Tier 1 (booking) | < 10 business days |
| Exception decision | < 5 business days (Tier 1/2), < 3 (Tier 3/4) |
| False-positive review for P1/P2 | < 2 business days |
| Platform availability (business hours) | 99.5% |
| Evidence ingestion latency (workflow complete → evidence visible) | p95 < 10 min |

## 7. How the TOM avoids gaming

| Gaming behaviour | Countermeasure |
|---|---|
| Disable scanner to reduce findings | Coverage and freshness are first-class metrics. A missing scan is `NO_EVIDENCE`, which is worse than having findings. |
| Mark findings false positive in bulk | FP rate is tracked per team. P1/P2 FPs need a second reviewer. FP decisions are sampled quarterly. |
| Re-scan on an unrelated branch to refresh evidence | Evidence must come from the default branch or the deployed artifact digest. The platform verifies the commit and the workflow identity. |
| Claim controls in `application.yaml` | Declared data (confidence C0) never satisfies a control. |
| Downgrade tier to reduce requirements | Downgrade requires AppSec approval. Tier history is retained and reported. |
| Long-lived exceptions | Maximum exception duration per tier. Renewals are counted and reported to leadership. |
