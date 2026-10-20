# 01 — Problem definition

| | |
|---|---|
| Status | Reference: the problem this project addresses and the reasoning behind its design |
| Related | [ADR-001](../../adr/ADR-001-platform-purpose-and-scope.md) · [Adoption kit](../../adoption-kit/README.md) |

## 1. Problem statement

Most organizations that build software can't answer, with evidence, whether a given application is built and run
securely. Their tools each see a slice: a code scanner, a dependency scanner, secret scanning, a cloud posture tool.
None of them knows:

- which **application** a repository, cloud account or finding belongs to;
- who **owns** that application, and how **critical** it is;
- which security **controls** that application is *required* to have;
- whether those controls are **operating**, as opposed to configured, claimed, or present in a YAML file;
- whether the **evidence** that a control operated is current, attributable and tamper-evident;
- what the resulting **risk** is, and whether it is being **remediated** on time;
- how all of this rolls up into **maturity** that leadership can track over time.

Without that context, maturity is assessed by questionnaire: a SAMM spreadsheet filled in once a year from memory.
The results can't be verified or compared, and they are out of date as soon as they are written.

## 2. The question the platform must answer

> **"For application X, which security controls are required, which are actually operating, what is the evidence,
> and what risk remains?"**

The organizational questions ("where are our biggest gaps?", "which applications are affected by CVE-X?", "what is
our SAMM maturity?") are aggregations over that per-application answer. If the per-application answer is wrong, every
aggregate built on it is wrong too.

## 3. A typical starting point

| Capability | Typical state |
|---|---|
| Scanners (SAST, dependencies, secrets, IaC, containers) | Licensed or running, configured per repository, results kept in each tool |
| Application inventory | Missing or a spreadsheet: no authoritative register of applications, owners, tiers or data classification |
| Control framework | Policies in prose, with no mapping from OWASP SAMM, ASVS or NIST SSDF to testable controls |
| Evidence | CI artifacts expire after days or weeks; nothing is retained, hashed or tied to the commit that shipped |
| Risk acceptance | A "risk accepted" flag in a scanner, with no owner, approver or expiry |
| Cloud posture | Findings not attributed to applications |
| Maturity | No baseline, or a self-assessment |

### 3.1 Common weaknesses this design avoids

Home-grown aggregation set-ups often hold more sensitive data than the tools around them, with weaker protection:

| Weakness | Consequence | How FortProof avoids it |
|---|---|---|
| Every repository holds an API key for the central scanner or finding store | Anyone with write access to any repository can read or alter every finding | The platform pulls evidence; repositories hold no platform credentials (ADR-006, ADR-028) |
| One database login shared by several components | Compromise of one gives full control of all | Each process has its own database login with only the rights it needs (ADR-008, ADR-015) |
| The finding store is reachable from the internet behind an IP allowlist | A map of exploitable weaknesses exposed to the network | Only the webhook receiver needs to be reachable (ADR-025) |
| Short log and backup retention, no tested restore | Below what audit evidence needs | Write-once evidence storage, retention defaults and a restore drill (ADR-017, ADR-026) |
| Findings written to two systems with no reconciliation | Dismissals diverge; "risk accepted" in a tool is not governed | Exceptions are owned by the platform, with approval and expiry; tool-level suppressions are not trusted (ADR-021) |
| Shared workflows referenced by branch (`@main`) | One change alters every consumer at once | Versioned workflow releases pinned by commit, approved before they count (ADR-006, ADR-028) |

## 4. Root causes

1. **No authoritative application context.** Findings attach to repositories, not applications, so risk can't be
   weighted by criticality or data sensitivity.
2. **Controls are not defined as testable statements.** "We do SAST" has no definition of scope, frequency, pass
   criteria or evidence.
3. **Evidence is ephemeral and unattributed.** A green tick in CI is not retained, signed or tied to the commit that
   reached production.
4. **Maturity is measured by self-assertion.** There is no link between SAMM answers and observable engineering
   activity.
5. **Tool-level state is mistaken for governance.** A "risk accepted" flag in a scanner is not a risk acceptance.

## 5. What success looks like

- Every in-scope application is registered, owned, classified, and linked to its repositories and cloud scopes.
- Every required control has a **machine-evaluated state** with a traceable chain: control → rule version → evidence
  IDs → raw artefact hash.
- Automated and manual evidence are **visibly distinguished**. Configuration alone never satisfies an execution
  control.
- "Which applications are affected by CVE-X?" is answered in seconds from SBOM inventory, including applications whose
  SBOM is stale. Those are flagged as *unknown*, not *unaffected*.
- SAMM maturity per application and per business unit is **derived from control states plus scheduled manual
  assessments**, with every score explainable.
- Exceptions are time-bound, owned and approved, and become findings automatically when they expire.

## 6. Non-goals

See [ADR-001](../../adr/ADR-001-platform-purpose-and-scope.md). In short: the platform does **not** replace the
scanners, Dependency-Track, DefectDojo, cloud posture tools or the SIEM. It does not run scanners itself; the shipped
pipelines run them in your CI. It is not a GRC suite for controls outside application security.

## 7. What it assumes, and what it doesn't

| Topic | Assumption |
|---|---|
| Source control | GitHub or GitLab. Signed (C3) pipeline evidence needs GitHub artifact attestations: public repositories, or GitHub Enterprise Cloud for private ones; GitLab evidence is capped at C2 ([ADR-033](../../adr/ADR-033-gitlab-evidence-trust.md)) |
| Sign-in | Any OpenID Connect identity provider (Entra ID, Okta, Keycloak, …) |
| Hosting | Any Kubernetes cluster (Helm chart) with PostgreSQL 16 and write-once object storage (S3 Object Lock or Azure Blob immutability) |
| Ticketing, SIEM, cloud posture | Optional integrations; none is assumed to exist |
| Scale | Designed for hundreds of applications and a few thousand repositories |
| Data classification | Your own labels; the classification profile is configurable, not hard-coded |
