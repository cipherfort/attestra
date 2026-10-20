# Software Supply Chain Security Standard

| | |
|---|---|
| ID | STD-09 · Status: Template. Adapt it and have it approved in your organization. |
| Owner | AppSec lead |
| Related | [ADR-028](../../adr/ADR-028-supply-chain-security.md), [ADR-029](../../adr/ADR-029-open-source-dependency-governance.md), [ADR-030](../../adr/ADR-030-build-provenance-and-artifact-integrity.md), SLSA v1.x Build track, NIST SSDF PS/PW.4 |

## 1. Threats addressed

Compromised dependencies (malicious or hijacked releases, typosquats) · compromised CI actions (as in the March 2026 `trivy-action` tag compromise) · credential theft from CI · artifact substitution between build and deploy · tampering with build environments · unreviewed code reaching production.

## 2. Requirements

| ID | Area | Requirement | T1 | T2 | T3 | T4 | Proven by |
|---|---|---|---|---|---|---|---|
| SSC-01 | Source | Default branch protected: review, CODEOWNERS on workflows and `.security/`, no force-push | ● | ● | ● | ○ | ASC-SRC-01/02 |
| SSC-02 | CI | Third-party actions pinned by full commit SHA. Only allowlisted actions. Minimal `permissions:`. No `pull_request_target` with untrusted checkout. | ● | ● | ● | ○ | ASC-SRC-06 |
| SSC-03 | CI | No long-lived cloud credentials. OIDC federation only. | ● | ● | ● | ○ | ASC-DEP-02 |
| SSC-04 | Dependencies | Lockfiles committed. Dependency review gate on PRs. | ● | ● | ○ | – | ASC-BLD-07 |
| SSC-05 | Dependencies | No malicious packages (hard block, no exceptions) | ● | ● | ● | ● | ASC-BLD-09 |
| SSC-06 | Dependencies | 3-day cooldown for non-security automated upgrades | ● | ● | ○ | ○ | Renovate/Dependabot config review |
| SSC-07 | Dependencies | Licence policy compliance | ● | ● | ● | ○ | ASC-BLD-08 |
| SSC-08 | Build | SBOM per release artifact | ● | ● | ● | ○ | ASC-BLD-03 |
| SSC-09 | Build | SLSA build provenance attestation for release artifacts (target Build L2; L3 with ephemeral isolated runners) | ● | ● | ○ | – | ASC-BLD-06 |
| SSC-10 | Build | Security workflows run on GitHub-hosted or ephemeral self-hosted runners | ● | ● | ○ | – | Confidence cap C2 otherwise |
| SSC-11 | Deploy | Verify provenance of the artifact digest before deployment | ● | ○ | – | – | ASC-DEP-03 |
| SSC-12 | Deploy | Base images pinned by digest and rebuilt at least every 30 days (Tier 1/2) | ● | ● | ○ | – | ASC-OPS-04 |
| SSC-13 | Publishing | Package publishing via trusted publishing (OIDC). No long-lived registry tokens. | ● | ● | ● | ● | Manual (release review) |
| SSC-14 | GitHub Apps | Third-party GitHub Apps installed only after security approval. Reviewed quarterly. | org-wide | | | | GitHub Security Baseline |

● mandatory · ○ recommended · – n/a

## 3. Incident response triggers

Advisory affecting an action or tool we use · malicious package detected · unexpected attestation failure · unapproved workflow evidence attempts. Response: [CVE emergency runbook](../runbooks/cve-emergency-response.md), evidence revocation ([evidence model section 5.3](../architecture/04-evidence-model.md#53-derived-state)), credential rotation.
