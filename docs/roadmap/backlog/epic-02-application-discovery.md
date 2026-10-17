# E02: Application Discovery

**Goal:** Find every repository, deployment and cloud scope that may belong to an application, so registration coverage can be measured against reality rather than self-reporting.

## F01: Repository discovery

### E02-F01-S01: Org-wide repository inventory · M · Phase 0 (script), Phase 2 (platform job)
- **Story:** As an AppSec engineer, I want an inventory of all repositories with activity, languages, visibility, GHAS enablement and Actions usage, so that we can size and target onboarding.
- **Value:** Baseline for coverage KPIs. Validates assumption A-06.
- **Technical:** Phase 0: Python script using the GitHub API (read-only token or App) → CSV/Parquet. Phase 2: becomes the `github-sync` discovery job writing `repositories`.
- **Depends on:** Phase 0: org read access. Phase 2: E06-F01 (GitHub App).
- **AC:** Every non-archived repo listed with `github_id`, visibility, default branch, languages, last push, GHAS features, workflows present. Archived repos are flagged, not omitted. A re-run is idempotent.
- **Security:** Output contains no code and no secrets. Stored internal-only.
- **Tests:** Unit tests with recorded API fixtures. Pagination tested beyond 100 items.
- **Tasks:** API client with pagination + ETags · fields · output · run · summary report.

### E02-F01-S02: Suggest application groupings · S · Phase 2
- **Story:** As a champion, I want suggested groupings of repos into applications (by topics, naming, CODEOWNERS team, shared deployment targets), so that registration is quick.
- **AC:** Given a team's repos, when suggestions are generated, then each suggestion lists its evidence (shared team, topic, name prefix, shared cloud scope), and accepting one pre-fills `application.yaml`.
- **Tests:** Heuristic unit tests on fixture org data.
- **Tasks:** heuristics · suggestion API · UI hook (E16).

## F02: Runtime discovery

### E02-F02-S01: Discover production deployments without a registered application · S · Phase 5–8
- **Story:** As AppSec lead, I want to find repos deploying to production (GitHub deployments to `prod*` environments, images running in cloud) that are not linked to a registered app, so that "dark" applications are surfaced.
- **AC:** A KRI "unregistered repos with production deployments" is computed daily. Each item links to its evidence (deployment record or resource).
- **Depends on:** E06-F02, E15-F01.
- **Tasks:** deployment scan · cloud image correlation · KRI metric.

### E02-F02-S02: Cloud scope discovery · C · Phase 8
- **Story:** As Cloud Security, I want subscriptions, resource groups and accounts listed with their `aap-app-id` tags, so that unattributed scopes can be assigned.
- **AC:** An unattributed-scopes report exists, with owner hints (tags, creator).
- **Depends on:** E15-F01.
