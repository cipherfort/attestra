# Pipeline Security Standard

| | |
|---|---|
| ID | STD-13 · Status: Template. Adapt it and have it approved in your organization. |
| Owner | AppSec Platform Product Owner |
| Related | [Pipeline architecture](../architecture/05-pipeline-architecture.md), [GitHub Security Baseline](github-security-baseline.md), [ADR-006](../../adr/ADR-006-github-actions-security-pipeline.md) |

## 1. Purpose

Secures CI/CD pipelines, which hold credentials and produce what reaches production, and standardises the security pipeline every application uses.

## 2. Requirements for all workflows

| ID | Requirement | Proven by |
|---|---|---|
| PIP-R01 | Declare top-level `permissions: {}` (or minimal) and grant per job only what is needed | ASC-SRC-06 (zizmor) |
| PIP-R02 | Pin every third-party action by full commit SHA with a version comment. Dependabot updates pins. | ASC-SRC-06 |
| PIP-R03 | Do not use `pull_request_target` or `workflow_run` to check out and execute untrusted (fork) code | ASC-SRC-06 |
| PIP-R04 | Do not interpolate untrusted context (`github.event.*.title`, `head_ref`, etc.) directly into `run:` scripts. Pass via environment variables. | ASC-SRC-06 |
| PIP-R05 | Cloud authentication via OIDC federation only. No static cloud credentials in secrets. | ASC-DEP-02 |
| PIP-R06 | Production deployments only through a protected `environment` with required reviewers (Tier 1/2) and restricted branches | ASC-DEP-01 |
| PIP-R07 | Use `persist-credentials: false` on checkout unless the job must push | ASC-SRC-06 |
| PIP-R08 | Download tools by pinned version with checksum verification. No `curl \| bash`. | Code review + zizmor |
| PIP-R09 | Secrets are scoped to environments, not repository-wide, where possible. No secrets printed or written to artifacts. | Review |
| PIP-R10 | Artifacts containing security output from public repos are retained ≤ 1 day | security-workflows default |

## 3. The security pipeline (paved road)

| ID | Requirement |
|---|---|
| PIP-S01 | Every onboarded repository has exactly one `.github/workflows/aap-security.yml` caller referencing `security-workflows` **by commit SHA** of a release |
| PIP-S02 | The pinned SHA must be in `config/trusted-producers.yaml`. Pins older than 90 days past their successor's release produce rejected evidence ("pin outdated"). |
| PIP-S03 | The caller grants only `contents: read`, `security-events: write`, `actions: read`, `id-token: write` and `attestations: write` |
| PIP-S04 | Teams do not fork or copy security workflows. Customisation is through documented inputs only. |
| PIP-S05 | The workflow runs on PR, on push to the default branch, weekly (staggered), and on manual dispatch. Build workflows pass built image refs. CD calls deploy-evidence. |
| PIP-S06 | For in-scope repos, an org ruleset requires the `aap-security` workflow (cannot be removed without an audited bypass) |

## 4. `security-workflows` repository (producer of evidence for every repo)

Two approvals from the platform team (CODEOWNERS), signed commits, no force-push · own CI: actionlint, zizmor, canary end-to-end on representative repos · tagged releases with release notes · release SHAs registered as trusted producers via PR to this repo · membership reviewed quarterly.

## 5. Runners

Security workflows run on GitHub-hosted runners or **ephemeral** self-hosted runners. Evidence from persistent self-hosted runners (e.g. a long-lived runner VM) is capped at confidence C2 until ephemeral runners are available (risk R-18).
