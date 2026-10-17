# 01 — Problem Definition and Current State

| | |
|---|---|
| Status | Reference: the problem this project addresses and the reasoning behind its design |
| Owner | Application Security Engineering |
| Related | [Programme Charter](../../adoption-kit/programme/charter/programme-charter.md), [ADR-001](../../adr/ADR-001-platform-purpose-and-scope.md) |

## 1. Problem statement

The organisation builds and runs a large and growing estate of applications. Their code is in GitHub and they run on Azure and AWS. Today we **cannot answer, with evidence, whether any given application is being built and run securely**. Several capabilities exist: GHAS Enterprise, Checkov, Microsoft Defender, Sentinel, and a scaffolded Dependency-Track and DefectDojo platform. But they are disconnected point tools. None of them knows:

- which **application** a repository, cloud subscription or finding belongs to;
- who **owns** that application, and how **critical** it is;
- which security **controls** that application is *required* to have;
- whether those controls are **operating**, as opposed to configured, claimed, or present in a YAML file;
- whether the **evidence** that a control operated is current, attributable and tamper-evident;
- what the resulting **risk** is, and whether it is being **remediated within SLA**;
- how all of this rolls up into **maturity** that leadership can track over time.

Without that context, application security maturity is assessed by questionnaire: a SAMM spreadsheet filled in once a year from memory. The results cannot be verified or compared, and they are out of date as soon as they are written.

## 2. The question the platform must answer

The single question behind the 25 questions in the programme brief is:

> **"For application X, which security controls are required, which are actually operating, what is the evidence, and what risk remains?"**

The organisational questions ("where are our biggest gaps?", "which apps are affected by CVE-X?", "what is our SAMM maturity?") are aggregations over that per-application answer. If the per-application answer is wrong, every aggregate is wrong. **The core product is therefore the Control → Evidence → Risk → Maturity engine, not the dashboard.**

## 3. Current state: what exists (verified from the earlier prototype scaffold, 2026-10-07)

| Capability | State | Notes |
|---|---|---|
| GitHub Advanced Security Enterprise | Licensed org-wide | CodeQL, secret scanning, Dependabot, dependency review, SARIF ingestion. **No Terraform dependency coverage, no container image scanning** (verified in ADR-0001 of the infra repo). |
| Checkov | Running on IaC repo PRs | Hard-fails some PRs today. |
| Dependency-Track 4.12 | **Scaffolded, not deployed** | SBOM ingestion and continuous CVE matching. CycloneDX only. |
| DefectDojo 2.42 | **Scaffolded, not deployed** | Finding normalisation, dedup and triage. Intended "single pane". |
| Reusable workflows | Written, piloted on one repo | `sbom-scan.yml`, `image-scan.yml`, `dependabot-import.yml`. Trivy pinned by SHA after the March 2026 `trivy-action` tag compromise (GHSA-69fq-xp46-6x23). |
| Hosting | Azure Container Apps, PG Flexible Server, Key Vault, OIDC from GitHub | IaC exists. |
| Application inventory | **None** | No authoritative register of applications, owners, tiers or data classification. |
| Control framework | **None** | No mapping from SAMM/ASVS/SSDF to testable controls. |
| Evidence | **None** | Workflow artifacts expire after 30 days; nothing is retained, hashed or attributable. |
| Exceptions / risk acceptance | **Informal** | DefectDojo "Risk Accepted" status has no owner, approver or expiry enforcement. |
| SAMM assessment | **None or manual** | No baseline. |
| Jira linkage | **None** | |
| Cloud posture → application linkage | **None** | Defender/Security Hub findings are not attributed to applications. |

### 3.1 Current-state security observations on the existing scaffold

These are not criticisms of an MVP that is explicitly marked "not yet deployed". They are inputs to this design, because the new platform will hold *more* sensitive data than the scaffold.

| # | Observation | Consequence | Addressed by |
|---|---|---|---|
| CS-1 | Every onboarded repo holds a **DefectDojo API v2 key and a Dependency-Track API key** as repository secrets. DefectDojo v2 keys are user-scoped and typically carry that user's full rights. | Anyone with write access to *any* onboarded repo can exfiltrate a key with platform-wide rights by pushing a workflow change. Blast radius grows with each onboarded repo. | ADR-005, ADR-006 (platform-mediated ingestion via GitHub App; no platform credentials in consumer repos) |
| CS-2 | PostgreSQL firewall rule `AllowAzureServices` (0.0.0.0) | Admits connections from **any** Azure tenant's services, not only ours. Password auth is the only remaining barrier. | ADR-025 (private endpoints, Entra auth) |
| CS-3 | DefectDojo and Dependency-Track share one PostgreSQL **admin** login | Compromise of either app gives full control of both databases. | ADR-008, ADR-015 |
| CS-4 | Public ingress plus IP allowlist; `DD_ALLOWED_HOSTS="*"` | Acceptable for an MVP; not for a store of exploitable vulnerability data. | ADR-025 |
| CS-5 | Log Analytics retention 30 days, PG backup 7 days, no tested restore | Below what audit evidence needs. | ADR-017, ADR-026 |
| CS-6 | Findings are dual-written to GHAS and DefectDojo with no reconciliation | Dismissals diverge. "Risk Accepted" in DefectDojo is not governed. | ADR-021 (exceptions are owned by the platform; tool-level suppressions are not trusted as risk acceptance) |
| CS-7 | Reusable workflows referenced `@main` | A change on `main` alters every consumer at once. | ADR-006, ADR-028 (versioned, SHA-pinned workflow releases) |

## 4. Root causes

1. **No authoritative application context.** Findings attach to repositories, not applications, so risk cannot be weighted by criticality or data sensitivity.
2. **Controls are not defined as testable statements.** "We do SAST" has no definition of scope, frequency, pass criteria or evidence.
3. **Evidence is ephemeral and unattributed.** A green tick in GitHub Actions is not retained, signed or tied to a commit that reached production.
4. **Maturity is measured by self-assertion.** There is no link between SAMM answers and observable engineering activity.
5. **Tool-level state is mistaken for governance.** A "risk accepted" flag in a scanner is not a risk acceptance.

## 5. What success looks like

- Every in-scope application is registered, owned, classified, and linked to its repositories and cloud scopes.
- Every required control has a **machine-evaluated state** with a traceable chain: control → rule version → evidence IDs → raw artefact hash.
- Automated and manual evidence are **visibly distinguished**. Configuration presence alone never satisfies an execution control.
- "Which applications are affected by CVE-X?" is answered in seconds from SBOM inventory, including applications whose scan is stale. Those are flagged as *unknown*, not *unaffected*.
- SAMM maturity per application and per business unit is **derived from control states plus scheduled manual assessments**, with every score explainable.
- Exceptions are time-bound, owned, approved, and become findings automatically when they expire.

## 6. Non-goals

See [ADR-001](../../adr/ADR-001-platform-purpose-and-scope.md). In short: the platform does **not** replace GHAS, Dependency-Track, DefectDojo, Defender or Sentinel. It does not run scanners itself. It is not a GRC suite for non-software risk. It does not produce a single "security score".

## 7. Assumptions (to be validated in Phase 0)

| ID | Assumption | Validation |
|---|---|---|
| A-01 | ~~GitHub Enterprise Cloud with GHAS for all in-scope orgs~~ | Not assumed: the plan is decision D-018 (ADR-031) |
| A-02 | Microsoft Entra ID is the workforce IdP | The project creates its app registrations and groups (ADR-031); see RAID A-02 |
| A-03 | Azure is the hosting platform for the platform itself | The project creates its own network and resources (ADR-031); see RAID A-03 |
| A-04 | Jira Cloud is the ticketing system | The project creates the site/project (ADR-031); see RAID A-04 |
| A-05 | Artifact attestations (Sigstore-backed) are available for private/internal repos | Requires GitHub Enterprise Cloud; verify on the org |
| A-06 | Order of magnitude: 100–500 applications, 300–2,000 repositories | Discovery in Phase 0 |
| A-07 | Data classification scheme exists (labels are configurable, not hard-coded) | Obtain from information governance |
| A-08 | The organisation has a SIEM: Sentinel, or another that accepts events over HTTPS or syslog | Confirm with SOC |
