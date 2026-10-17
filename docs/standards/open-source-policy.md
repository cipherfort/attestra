# Open Source Security Policy

| | |
|---|---|
| ID | STD-14 · Status: DRAFT. REQUIRES HUMAN APPROVAL (Legal for licensing, CISO for security). |
| Owner | Head of Application Security, with OSS governance / Legal |
| Related | [ADR-028](../../adr/ADR-028-supply-chain-security.md), [ADR-029](../../adr/ADR-029-open-source-dependency-governance.md), [`config/licence-policy.yaml`](../../config/licence-policy.yaml) |

> **Core rule: PUBLIC SOURCE CODE ≠ PUBLIC SECURITY EVIDENCE.** Making source code public never makes its findings, SBOMs, threat models, scan results or exceptions public.

## 1. Consuming open source

| ID | Requirement |
|---|---|
| OSS-C01 | Dependencies must have licences allowed by the licence policy for the application's distribution model. Denied licences need a Legal exception. (ASC-BLD-08) |
| OSS-C02 | Malicious or compromised package versions are blocked without exception (ASC-BLD-09) |
| OSS-C03 | New direct dependencies should be actively maintained (release or commit within 12 months). The OpenSSF Scorecard result is shown in PR review (informational). |
| OSS-C04 | Lockfiles are committed. Automated upgrades use a 3-day cooldown except for security fixes. |
| OSS-C05 | Vendored or copied code is recorded in the SBOM (CycloneDX component with `pedigree`), with its licence |

## 2. Maintaining forks

| ID | Requirement |
|---|---|
| OSS-F01 | Forks of upstream projects are registered as application components with an `upstream` reference |
| OSS-F02 | Forks track upstream security releases. Divergence age is reported. Security fixes are merged within the SLA for their priority. |
| OSS-F03 | Patches are contributed upstream where possible to reduce fork divergence |

## 3. Publishing open source

| ID | Requirement |
|---|---|
| OSS-P01 | Making a repository public requires an open-source approval record (security review, licence choice, secrets history scan, removal of internal references). Visibility is checked by ASC-SRC-05. |
| OSS-P02 | Before first publication, the full git history is scanned for secrets. Any found are rotated before publishing. |
| OSS-P03 | Public repositories enable private vulnerability reporting and publish `SECURITY.md` |
| OSS-P04 | Security workflows on public repos print counts only. No finding detail in logs, summaries or PR comments. Artifacts retained ≤ 1 day. |
| OSS-P05 | Embargoed fixes are developed in GitHub Security Advisory private forks, not in public branches |
| OSS-P06 | Releases are signed tags with provenance attestations. Packages are published via trusted publishing (OIDC). |
| OSS-P07 | Public SBOM publication is an explicit per-release decision, not a default |

## 4. External contributors

| ID | Requirement |
|---|---|
| OSS-X01 | Contributions under CLA or DCO as decided by Legal |
| OSS-X02 | Workflows from first-time and outside contributors require maintainer approval to run. Fork PRs have no secrets and read-only tokens. |
| OSS-X03 | All external PRs need CODEOWNERS review. Changes to `.github/workflows/` from external contributors need AppSec review. |
| OSS-X04 | Evidence from fork PRs never satisfies controls |

## 5. GitHub Actions and Apps from third parties

Allowlisted actions only, pinned by SHA ([Pipeline Security Standard](pipeline-security-standard.md)). Third-party GitHub Apps need security approval ([GitHub Security Baseline GH-07](github-security-baseline.md#1-enterprise-and-organisation-settings)).
