# GitHub Security Baseline

| | |
|---|---|
| ID | STD-12 · Status: Template. Adapt it and have it approved in your organization. Applied by the project's organization owner (`examples/terraform/azure/envs/github`, ADR-031). |
| Owner | AppSec lead, with the project's GitHub organization owner (ADR-031) |
| Applies to | All GitHub organisations holding in-scope code (e.g. `example-org`) |
| Implementation | Settings as code via the Terraform `integrations/github` provider in a dedicated `github-org-config` repository (recommended). Drift is detected by the platform's GitHub connector. |

> Feature names and availability change. **Verify each setting against current GitHub Enterprise Cloud documentation and the organisation's plan before you adopt it** (assumption A-01). Where a setting is unavailable, record the gap and the compensating control.

## 1. Enterprise and organisation settings

| ID | Setting | Baseline | Why | Verified by |
|---|---|---|---|---|
| GH-01 | Authentication | SSO through the organization's identity provider enforced for the enterprise or organization. Evaluate Enterprise Managed Users for central lifecycle. | Joiner/mover/leaver control | Annual review |
| GH-02 | Two-factor authentication | Required for all members and outside collaborators | Account takeover | Org setting (connector) |
| GH-03 | Base repository permission | `Read` or `No permission`. Access via teams synced from identity-provider groups. | Least privilege | ASC-SRC-05 |
| GH-04 | Repository creation | Members may create private/internal repos only. Public repos via the open-source approval process. | Accidental publication | ASC-SRC-05 |
| GH-05 | Repository visibility change, deletion, transfer | Org owners only | Data exposure, evidence loss | Audit log |
| GH-06 | Personal access tokens | Fine-grained PATs require approval with a maximum lifetime. Classic PATs restricted. | Token sprawl | Annual review |
| GH-07 | GitHub Apps / OAuth apps | Installation requires security approval. Inventory and quarterly permission review. | Third-party access | ADR-028 |
| GH-08 | Actions: allowed actions | GitHub-owned + verified creators + explicit allowlist | Supply chain (T-14) | ASC-SRC-06 |
| GH-09 | Actions: default `GITHUB_TOKEN` | Read-only. Actions cannot create or approve PRs. | Privilege | ASC-SRC-06 |
| GH-10 | Actions: fork PR workflows | Require approval for first-time and outside contributors | Untrusted code execution | Org setting |
| GH-11 | Self-hosted runners | Not used by public repositories. Runner groups restricted to selected repos. Ephemeral for security workflows. | Runner compromise (T-03) | Confidence cap |
| GH-12 | Security features (code security configuration) | Applied to all repos: dependency graph, Dependabot alerts and security updates, secret scanning with push protection and validity checks, code scanning (CodeQL default setup or `aap-security` advanced setup), private vulnerability reporting | Detection coverage | ASC-SRC-03, ASC-BLD-01/02 |
| GH-13 | Push protection bypass | Bypass requires a reason. Bypasses are ingested as findings and reviewed. | Secret leakage | ASC-SRC-04 |
| GH-14 | Org rulesets | Default-branch ruleset for in-scope repos (see section 2). "Require workflow" rule for `aap-security`, targeted by the `aap_tier` custom property. | Enforce the paved road | ASC-SRC-01 |
| GH-15 | Repository custom properties | `aap_app_id`, `aap_tier` (set by the platform onboarding process) | Ruleset targeting, discovery | Connector |
| GH-16 | Audit log streaming | Stream to Azure Event Hubs → Sentinel. Retention per the SOC. | Detection, investigations | SOC |
| GH-17 | IP allow list | Enterprise IP allow list where feasible. The platform GitHub App IP allow list is enabled. | Token misuse (T-10) | Annual review |
| GH-18 | Deploy keys | Disabled by default. Exceptions are read-only keys with an owner. | Credential sprawl | Connector (repo.access) |
| GH-19 | Webhooks | Org/repo webhooks only to approved destinations, with secrets set | Data exfiltration | Annual review |

## 2. Default-branch ruleset (in-scope repositories)

| Rule | Tier 1 | Tier 2–3 | Tier 4 |
|---|---|---|---|
| Require pull request | ✓ | ✓ | ✓ |
| Required approvals | 2 | 1 | 1 |
| Dismiss stale approvals on push | ✓ | ✓ | ○ |
| Require review from code owners | ✓ | ✓ | ○ |
| Require approval of the most recent push (by someone other than the pusher) | ✓ | ✓ | ○ |
| Required status checks | `aap / sast`, `aap / sca`, `aap / secrets` (+ `aap / dependency-review` when gated) | same | ○ |
| Require conversation resolution | ✓ | ○ | ○ |
| Block force pushes and deletion | ✓ | ✓ | ✓ |
| Require signed commits | ○ (✓ for `security-workflows`, the platform repo) | ○ | ○ |
| Require linear history | ○ | ○ | ○ |
| Bypass list | Named break-glass team only. Bypass is audited. | same | same |

## 3. Repository baseline

Valid `CODEOWNERS` covering `.github/workflows/` and `.security/` (ASC-SRC-02) · `SECURITY.md` (org default allowed, ASC-GOV-05) · `.security/application.yaml` (ASC-GOV-01) · `aap-security.yml` caller pinned by SHA (Pipeline Security Standard) · no repository secrets holding cloud credentials (ASC-DEP-02) · production `environment` with required reviewers for Tier 1/2 (ASC-DEP-01).
