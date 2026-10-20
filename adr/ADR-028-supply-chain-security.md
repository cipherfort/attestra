# ADR-028: Software supply-chain security (platform, workflows and open-source estate)

**Status:** Accepted (2026-10-20), implemented  ·  **Related:** ADR-006, ADR-029, ADR-030, controls ASC-SRC-06, ASC-BLD-06/07/09

## Context

CI/CD and dependencies are now primary attack paths. The organisation has direct experience: the March 2026 `trivy-action` tag compromise (GHSA-69fq-xp46-6x23) forced SHA pinning in the infra repo. Many target applications are open source or public, which needs explicit handling.

## Decision

### A. GitHub Actions
- Enterprise/org **Actions allowlist**: GitHub-owned, verified creators, and an explicit list of third-party actions. Others are blocked.
- **SHA pinning** for all third-party actions (enforced by ASC-SRC-06 via zizmor). Dependabot updates the pins.
- Org default `GITHUB_TOKEN` permissions: **read-only**. Workflows declare `permissions` explicitly.
- `pull_request_target` banned in security workflows. Its use elsewhere is flagged by workflow lint.
- First-time and outside contributors' fork PR workflows **require approval** (org setting).
- **GitHub Apps** installation requires security approval. Inventory and permission review quarterly.

### B. The platform's own build
- Lockfiles (`uv.lock`, `package-lock.json`). Dependency review on PRs. Dependabot/Renovate with a **minimum release age (cooldown) of 3 days** for non-security updates (ADR-029).
- Minimal, **digest-pinned** base images. No `curl | bash`. Tool downloads checksum-verified.
- Images get SLSA provenance via `actions/attest-build-provenance`. CD verifies it before deploy (ADR-030).
- Branch protection, signed commits and 2-reviewer CODEOWNERS on `security-workflows`, `catalogue/` and `config/`.
- OpenSSF Scorecard on platform repos (PROPOSED, informational).

### C. Open-source and public repositories: **public source ≠ public evidence**
| Topic | Policy |
|---|---|
| Security evidence and findings for public repos | **Internal.** Never written to public PR comments, issues, logs or job summaries. Workflow output on public repos prints counts only. Artifacts retained 1 day. |
| GHAS alerts on public repos | Visible only to users with security-alert access (GitHub default). Do not widen. |
| Vulnerability disclosure | Via the private vulnerability reporting / GitHub Security Advisories workflow. Embargoed fixes developed in private forks (GHSA temporary private forks). |
| External contributors | CLA/DCO per OSS policy. First-time contributor workflow approval. CODEOWNERS review. No secrets available to fork PRs. |
| Forks of upstream projects (we maintain a fork) | Registered as an application component with an `upstream` reference. A sync cadence is tracked. A divergence-age metric is reported. |
| Release integrity | Signed tags. Release artifacts with provenance attestations. Published SBOM optional per project decision. |
| Package publishing | Trusted publishing (OIDC) to registries that support it (npm, PyPI). No long-lived publish tokens. |

## Alternatives considered

Tag pinning (proven unsafe by the trivy-action incident) · blanket ban on third-party actions (impractical) · trusting public-repo visibility settings for evidence (leaks).

## Decision drivers

Lessons from real incidents · least privilege in CI · protecting internal evidence for public code.

## Consequences

Friction from allowlist requests (provide an SLA). Pin maintenance (automated).

## Security implications

Addresses threats T-14, T-15 and T-16.

## Operational implications

Allowlist governance (AppSec). Quarterly GitHub App review. Org-level settings are applied by the project's own organization owner through `examples/terraform/azure/envs/github` (ADR-031).
