# Platform Security Architecture and Threat Model

| | |
|---|---|
| Status | DESIGNED: requires review by AppSec (independent of the platform team) before Phase 1 exit |
| Classification of this document | Internal |
| Related ADRs | 013–017, 022, 025, 027, 028, 030, 032, 033 |
| Last threat-model refresh | 2026-10-16 (M5: open-source product, plugins, GitLab, packaging; section 4.1) |

The platform holds an **organisation-wide map of exploitable weaknesses**: which apps are vulnerable, how, and who owns them. It is a high-value target. It must be the best-secured application in the estate. It must also be onboarded to *itself* as a Tier 1 application.

## 1. Security objectives

| ID | Objective |
|---|---|
| SO-1 | Unauthorised parties cannot read vulnerability or evidence data, including other business units' data where scoped. |
| SO-2 | Evidence cannot be forged, altered or deleted undetectably, including by platform administrators. |
| SO-3 | A compromise of any consumer repository cannot compromise the platform or other repositories' evidence. |
| SO-4 | A compromise of the platform cannot be used to change code in consumer repositories (GitHub App is **read-only**). |
| SO-5 | Control states and maturity cannot be manipulated without an auditable trail. |
| SO-6 | The platform remains available enough to support CVE response (RTO 4h, RPO 15 min). |

## 2. Trust boundaries

```
 Internet ──TB1──▶ aap-hook (HMAC-verified, enqueue only)
 Internet ──TB1──X  aap-web (NOT exposed; reachable only via corporate network / ZTNA)
 Corporate users ──TB2──▶ aap-web (Entra OIDC, Conditional Access, BFF session)
 aap-web / aap-worker ──TB3──▶ PostgreSQL, Blob, Key Vault (private endpoints, managed identity)
 aap-worker ──TB4──▶ GitHub API, Jira, DD, DT, Azure, AWS, public feeds (egress allowlist)
 Consumer repo workflows ──TB5──▶ GitHub (artifacts, attestations): NOT directly to the platform
```

## 3. Controls by domain

### 3.1 Identity and access

| Control | Design | Status |
|---|---|---|
| Workforce authN | Entra ID OIDC auth code + PKCE via BFF. Session cookie `__Host-` prefixed, `HttpOnly; Secure; SameSite=Lax`, 8h absolute and 30 min idle. Conditional Access: compliant device + MFA. | DESIGNED |
| Service authN | Managed identities for Azure resources. GitHub App JWT → installation token (1h). Jira service account token in Key Vault. | DESIGNED |
| AuthZ model | RBAC + scope (org unit / application) evaluated in the API **and** PostgreSQL RLS as defence in depth ([ADR-013](../../adr/ADR-013-rbac-model.md)). Deny by default. | DESIGNED |
| Role source | Entra groups → platform roles. App-level roles derived from `application.yaml` owners (GitHub teams) cross-checked against Entra. | DESIGNED |
| Privileged access | `platform-admin` via Entra PIM (just-in-time, approval, 4h max). Break-glass account monitored by Sentinel. | DESIGNED |
| Segregation of duties | Exception requester ≠ approver. Manual-assessment reviewer ≠ member of the app team. False-positive confirmer for P1/P2 ≠ marker. **Enforced in code, not policy.** | DESIGNED |
| Admins cannot rewrite evidence | The DB role used by the app has no UPDATE/DELETE on ledger tables. The blob container has a WORM policy. | DESIGNED |

### 3.2 Data protection

| Control | Design |
|---|---|
| In transit | TLS 1.2+ everywhere, TLS 1.3 preferred. Private endpoints for PG, Blob and Key Vault. `sslmode=verify-full` to PG. |
| At rest | Platform-managed encryption by default. **Customer-managed keys (Key Vault) for PG and Blob — PROPOSED, REQUIRES HUMAN APPROVAL** (cost and key-ops overhead vs data sensitivity). |
| Sensitive fields | Secret-scanning findings store **only** the secret type, location, fingerprint and validity. **Never the secret value.** Raw secret-scanner output is redacted by the ingestion worker before it reaches WORM storage. |
| Public vs internal | A public repository's *code* is public. Its *security evidence and findings are not* ([ADR-028](../../adr/ADR-028-supply-chain-security.md), "Open source" section). The platform never writes findings back to public repos (no PR comments with vuln detail on public repos). SARIF to the GHAS tab is acceptable because GitHub restricts code-scanning alert visibility to users with security-alert access. |
| Data minimisation | Developer identity is limited to GitHub login + Entra object ID where linked. No commit-level productivity metrics. See the [privacy considerations](#6-privacy-considerations). |

### 3.3 Evidence integrity ([ADR-016](../../adr/ADR-016-evidence-immutability.md))

1. **Provenance:** pipeline evidence is accepted only from an **approved reusable workflow path at an approved commit SHA**. This is verified twice: (a) `referenced_workflows` on the workflow run from the GitHub API, and (b) the Sigstore certificate's Build Signer URI on the artifact attestation.
2. **Content integrity:** the SHA-256 of every raw file is in the signed manifest. The ingestion worker recomputes it and rejects a mismatch.
3. **Storage immutability:** raw artefacts go to a Blob container with **version-level immutability (time-based retention, locked)**. Not even a subscription owner can delete them before expiry.
4. **Ledger immutability:** the `evidence` table is append-only. It is enforced by (a) DB grants (no UPDATE/DELETE for the application role), (b) a trigger that raises on UPDATE/DELETE, and (c) a **hash chain**: each record carries `prev_hash` within its partition, and a daily checkpoint (root hash + count) is written to the WORM container and emitted to Sentinel. Tampering by a DB superuser breaks the chain, and the externally anchored checkpoint shows it.
5. **Verification job:** a daily job recomputes chain hashes and samples blob hashes. A failure raises a P1 platform incident.

### 3.4 Application security of the platform

| Threat class | Control |
|---|---|
| Injection | SQLAlchemy parameterised queries only. A lint rule bans string-built SQL. Filtering/sorting is via allowlisted fields. |
| SSRF | Connectors call **configured base URLs only** (no user-supplied URLs). Egress goes through an Azure Firewall / NAT allowlist. The evidence `raw_location` is platform-generated, never user-supplied. Webhook payload URLs are ignored; resources are re-fetched by ID from the GitHub API. |
| Deserialisation / parser attacks | Scanner outputs are untrusted input. They are parsed with size limits (artifact ≤ 200 MB, JSON depth limits) and safe loaders (`yaml.safe_load`, `defusedxml`) in a worker with no inbound network and least-privilege identity. Zip bomb protection on artifact download (ratio + total size limits). |
| File handling | No user file upload in v1 except manual-evidence attachments: type allowlist (PDF, PNG, MD, TXT, JSON), Defender for Storage malware scanning, served with `Content-Disposition: attachment` from a separate origin. |
| XSS | React escaping by default. Strict CSP (`default-src 'self'`; no inline script). Markdown rendered with a sanitiser. Scanner-provided strings (titles, descriptions) are treated as untrusted. |
| CSRF | SameSite cookie + double-submit token on state-changing BFF routes. |
| AuthZ bypass / IDOR | Every resource fetch is scoped by the caller's permitted org units in the repository layer. RLS backs it up. An access-control test matrix runs in CI ([test strategy](../roadmap/backlog/epic-22-testing.md)). |
| Rate limiting | Per-identity token-bucket limits at the API (per replica; good enough at 2–6 replicas, so no Redis dependency), plus stricter limits on export endpoints. Webhook receiver: per-source limits plus Container Apps scale ceiling. |
| Webhook spoofing | HMAC-SHA256 (`X-Hub-Signature-256`) with constant-time compare. Delivery-ID replay cache (24h). The payload is treated as a *hint*: the worker re-fetches state from the GitHub API. |
| Secrets | Key Vault only, accessed via managed identity. No secrets in env files, Terraform state outputs or logs. The GitHub App private key is in Key Vault ([ADR-015](../../adr/ADR-015-secrets-management.md)). |

### 3.5 Supply chain of the platform itself

Covered in [ADR-028](../../adr/ADR-028-supply-chain-security.md) and [ADR-030](../../adr/ADR-030-build-provenance-and-artifact-integrity.md):
- dependencies pinned via lockfiles (`uv.lock`, `package-lock.json`); third-party Actions pinned by SHA; Dependabot/Renovate updates;
- container images built from minimal base images pinned by digest; signed (Sigstore) and provenance-attested;
- deployment verifies the attestation before rollout (`gh attestation verify` in CD, and Container Apps pulls only from the platform ACR by digest);
- the platform consumes **its own** reusable security workflows. Dogfooding is a Phase 1 exit criterion.

### 3.6 Resilience

| Item | Target / design |
|---|---|
| RTO / RPO | 4h / 15 min (PG PITR, zone-redundant HA). Cross-region restore runbook. |
| Backups | PG automated backups 35 days plus long-term monthly backups (Azure Backup for PG Flexible) for 12 months. Evidence blob: GRS + immutability. |
| DR | Cold standby in a paired region via Terraform. Restore drill every 6 months ([ADR-026](../../adr/ADR-026-disaster-recovery.md)). |
| Degraded mode | If GitHub/Jira/DD are unavailable, jobs retry with backoff. Evidence is not lost because GitHub retains artifacts (configure ≥ 7 days). The UI shows connector health. |

## 4. Threat model: the platform (STRIDE)

Scope: the components and trust boundaries above. Ratings are inherent → residual (after listed controls). Scale: L/M/H.

| ID | Component / flow | STRIDE | Threat | Inherent | Controls | Residual |
|---|---|---|---|---|---|---|
| T-01 | Consumer repo → evidence | **S**poofing | A malicious repo maintainer fabricates a "clean SAST" evidence bundle from a hand-written workflow | H | Approved-workflow verification (referenced_workflows + attestation signer). Manifest produced inside the reusable workflow. | L |
| T-02 | Consumer repo → evidence | **T**ampering | The maintainer alters the code *after* the scan, so evidence refers to a commit that differs from what is deployed | M | Evidence is bound to `head_sha` and, for artifacts, to digest. Deployment evidence links the digest to the environment. A mismatch yields `NO_EVIDENCE` for the deployed version. | L |
| T-03 | Reusable workflow running on a persistent self-hosted runner | **T**ampering | A prior job on the same runner poisons the toolchain (e.g. replaces the scanner binary) | M | Ephemeral runners for security workflows (ARC/ephemeral VM, or GitHub-hosted). Tool binaries are verified by checksum. Recorded as the `runner_environment` attribute; evidence from non-ephemeral runners is capped at confidence C2. | M (until ephemeral runners exist) |
| T-04 | Webhook receiver | **S**poofing / **D**oS | Forged or replayed webhooks; flooding | M | HMAC, replay cache, payload-as-hint, ingress IP restriction to GitHub `hooks` ranges (from `/meta`), rate limits, scale ceiling | L |
| T-05 | Workers parsing scanner output | **E**levation | Malicious SARIF/SBOM exploits a parser (e.g. YAML deserialisation, zip bomb, XXE) | M | Safe loaders, limits, isolated worker identity with no Key Vault access beyond needs, no outbound except allowlist | L |
| T-06 | API | **I**nfo disclosure | IDOR: user in business unit A reads app B's findings | H | Scoped repository layer + RLS + authZ test matrix in CI | L |
| T-07 | API | **E**levation | User self-approves an exception or confirms their own false positive | M | SoD enforced in the workflow engine. Audit event. Sentinel analytics rule on SoD-override attempts. | L |
| T-08 | DB | **T**ampering | DBA or compromised admin rewrites evidence or control states to inflate maturity | M | Append-only grants and trigger, hash chain, external checkpoint, daily verification, PIM for DB admin | L |
| T-09 | DB / Blob | **I**nfo disclosure | Exfiltration of the vulnerability map | H | Private endpoints, no public network access, Entra auth to PG, Defender for Databases/Storage, egress allowlist, audit of bulk export | M |
| T-10 | GitHub App key | **E**levation | App private key stolen; attacker reads all repos (including private code) | H | Key in Key Vault (HSM-backed if Premium), read-only app permissions, **no `contents:write`**, IP allow list on the GitHub App (Enterprise), rotation every 90 days, alert on token use from an unexpected IP | M |
| T-11 | Jira integration | **I**nfo disclosure | Ticket contents (vuln details) visible to a wide Jira audience | M | Dedicated Jira project(s) with issue security levels. Tickets carry the minimal detail plus a link back to the platform. | L |
| T-12 | Platform admin | **R**epudiation | Admin changes the risk model to downgrade priorities and denies it | M | Risk model and control catalogue are **version-controlled config** (PR + review), loaded by digest. Runtime changes are disabled. Every evaluation stores the model version. | L |
| T-13 | Upstream tool (DT/DD) | **T**ampering | Compromised DefectDojo marks findings mitigated en masse | M | Platform closure requires its own evidence (re-scan). Mass-closure anomaly detection (> N closures/hour → alert). | L |
| T-14 | Third-party Actions in reusable workflows | **T**ampering | Compromised action tag (as with `trivy-action`, Mar 2026) exfiltrates secrets | H | SHA pinning, Actions allowlist at the enterprise level, minimal `permissions:`, **no platform secrets in workflows** (pull model), harden-runner egress audit (PROPOSED) | L |
| T-15 | Public repos | **I**nfo disclosure | Evidence or findings for a public repo leak via PR comments, workflow logs or artifacts | M | Reusable workflows detect `github.event.repository.visibility == 'public'`, suppress detail in logs and job summaries, and set artifact retention to 1 day (the platform pulls immediately) | L |
| T-16 | Fork PRs on public repos | **E**levation | `pull_request_target` misuse runs untrusted code with secrets | H | Reusable workflows **never** use `pull_request_target`. The platform does not depend on fork-PR evidence. Org policy: approval required for first-time contributors. | L |
| T-17 | Availability | **D**oS | Platform outage during a CVE emergency | M | HA PG, multi-replica web, read-only degraded mode, CVE query also runnable directly against Dependency-Track as a fallback (runbook) | L |
| T-18 | Maturity metrics | **T**ampering (gaming) | Teams game metrics (see TOM section 7) | M | Metric design + sampling audits | M |

**Residual risks to accept explicitly (REQUIRES HUMAN APPROVAL):** T-03 until ephemeral runners exist, T-09 (inherent to an aggregated vuln store), T-10 (GitHub App read access to all code is inherent to the design), T-18.

### 4.1 Refresh for the open-source product (M5, 2026-10-16)

The product added plugins, a second source-control platform, write-capable integrations, administration and new
deployment forms. Each new threat below names its control and the test that holds it; "Residual" is after controls.

| # | Where | STRIDE | Threat | Control | Tested by | Residual |
|---|---|---|---|---|---|---|
| T-19 | Plugins (entry points) | **E**levation | A third-party plugin package runs code inside the worker with its database role and secrets | Plugins are Python packages the operator installs (no runtime download). A plugin that fails to load is reported, not fatal. Plugins run in the worker, never in the API or hook. Documented: install plugins only from sources you trust, pin by hash | `test_plugins.py` (broken plugin isolated) | M (inherent to in-process plugins) |
| T-20 | GitLab CI components | **S**poofing | A project includes the approved component and overrides its job to fabricate clean results | Merged job compared to the component file at the approved SHA; unpinned includes refused; `inherit: default/variables: false` required ([ADR-033](../../adr/ADR-033-gitlab-evidence-trust.md)) | `test_gitlab_live.py` (a real forged job with a valid manifest is rejected), `test_gitlab.py` | M: CI/CD variables can still influence the job; evidence capped at C2 |
| T-21 | GitLab webhook | **S**poofing | Forged job events trigger ingestion of attacker-chosen jobs | Secret token compared in constant time; payload is a hint (job re-read through the API, bound to the project); polling fallback ingests each job once | `test_gitlab.py` (bad token → 401), ingestion idempotency in the live test | L |
| T-22 | Issue writers (GitHub/GitLab Issues) | **E**levation | The write credential for issues is used to change code or settings | GitHub: a separate installation token narrowed to `issues: write` + `metadata: read`; the read connectors never hold it. GitLab: a separate Reporter token (cannot push). Content is identifiers and a link, never exploit detail | `test_issues.py`, GitLab issues live test | L |
| T-23 | Administration | **E**levation | An administrator grants themselves AppSec or leadership rights, or a compromised API changes scopes | Separate `aap_admin` database role used only by `org.admin` endpoints; no self-grants; `platform_admin` only from the identity provider; re-parenting units not exposed; every change and refusal audited | `test_admin.py` (including the role's database permissions) | L |
| T-24 | CSV export | **T**ampering (downstream) | Finding titles from scanners carry spreadsheet formulas (CSV injection) | Cells starting with `= + - @` (and tab, carriage return) are prefixed; exports are scoped by row-level security and audited | `test_reports_notify.py` | L |
| T-25 | Vulnerability feeds | **T**ampering | A truncated or poisoned KEV/OSV/EPSS response lowers priorities | KEV refuses implausible catalogues (count and minimum size); OSV only adds or removes links on complete runs; feeds raise priorities, they never close findings; HTTPS only, mirrors configurable | `test_vuln_feeds*.py` | L |
| T-26 | Evidence parsers | **D**oS / **E**levation | Malformed SARIF, SBOM, JUnit, archives or CI configuration crash ingestion or exploit a parser | Size limits before parsing; DOCTYPE/ENTITY refused in XML; every parser raises only its own error, rejected bundles leave nothing written (savepoint); property-based fuzzing in CI (200 examples) and nightly (5,000) | `tests/fuzz/test_parsers.py`, `test_thin_slice.py` | L |
| T-27 | Notifications / SIEM sinks | **I**nfo disclosure | Chat channels or a misconfigured sink receive sensitive data | Notifications carry identifiers and links only; HTTPS (webhooks, HEC) or TLS with certificate verification (syslog); one SIEM sink at a time | `test_reports_notify.py`, `test_siem_sinks.py` (untrusted syslog server refused) | L |
| T-28 | Helm deployment | **E**levation | A compromised pod reaches the cloud metadata service, other namespaces or secrets it does not need | Non-root, read-only root filesystem, no capabilities, seccomp, no service-account token; each process mounts only its secret keys (0440); NetworkPolicies default-deny with egress never to 169.254.169.254; IRSA/workload identity, no storage keys | `charts/attestra/ci/smoke.sh` (UID 10001, read-only root, per-process logins), values schema refuses weaker settings | M: NetworkPolicy has no FQDN rules (egress to 443 is broad unless a proxy or CNI policy narrows it) |
| T-29 | Releases | **T**ampering | A tampered image or chart is installed | Images and chart signed with cosign keyless and SLSA provenance by `release.yml`; installation docs verify both before install; base images pinned by digest | Release workflow (runs on the first tag) | L once the first release is verified end to end |
| T-30 | Compose evaluation stack | **I**nfo disclosure | Evaluation secrets or data reused in production | Secrets generated per installation, mode 700 directory, git-ignored; `env: development`; documentation states it is not for production | Manual review | L |

## 5. Abuse cases (drive security tests)

| AC | As a… | I try to… | Expected |
|---|---|---|---|
| AC-01 | repo maintainer | upload a hand-crafted `evidence-manifest.json` from my own workflow | Rejected: `UNTRUSTED_PRODUCER`. Audit event. |
| AC-02 | repo maintainer | reference the approved workflow at an unapproved SHA (my fork of it) | Rejected: `UNAPPROVED_WORKFLOW_REF` |
| AC-03 | business unit user | GET `/api/v1/applications/{id-of-other-business unit}` | 404 (not 403, to avoid enumeration) |
| AC-04 | exception requester | approve my own exception via the API | 403 `SOD_VIOLATION`. Audit event. |
| AC-05 | platform admin | UPDATE an evidence row via SQL | Error from trigger. The chain verification also detects superuser bypass. |
| AC-06 | anyone | send a webhook with a valid shape and wrong HMAC | 401. No enqueue. |
| AC-07 | anyone | trigger a 10 GB zip artifact | Download aborted at the limit. Evidence `REJECTED_SIZE`. |
| AC-08 | anyone | put `<script>` into a finding title via a malicious SARIF | Rendered inert (escaping + CSP) |
| AC-09 | app owner | lower my app's tier | Change held `PENDING_APPROVAL`. Requirements unchanged until approved. |
| AC-10 | user | export all findings org-wide | Allowed only for `security-leadership`/`appsec-engineer`. Bulk export audit event goes to Sentinel. |

## 6. Privacy considerations

The platform processes personal data in a limited form: names, emails, GitHub logins and Entra IDs of owners, champions, reviewers and approvers; actor identities in audit logs; commit author identity inside raw scanner output (e.g. secret-scanning commit metadata).

- **Purpose limitation:** security assurance only. The platform **must not** be used for individual performance management. Per-person metrics are not built (team level only). This is stated in the DPIA and the acceptable-use notice.
- **Minimisation:** commit author emails are stripped from normalised records where not needed. Raw artefacts retain them, under restricted access.
- **Retention:** see [ADR-017](../../adr/ADR-017-evidence-retention.md).
- **Lawful basis and DPIA:** **REQUIRES HUMAN APPROVAL.** The Data Protection Officer must confirm whether a DPIA is required (employee monitoring considerations) and the applicable lawful basis. This design does not claim compliance with UK GDPR / DPA 2018 or any other regime.
