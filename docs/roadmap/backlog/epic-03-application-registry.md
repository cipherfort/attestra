# E03: Application Registry

**Goal:** An authoritative, verified register of applications, owners, tiers, repositories, environments and cloud scopes.

## F01: Application contract ingestion

### E03-F01-S01: Validate and ingest `.security/application.yaml` · M · Phase 2
- **Story:** As a technical owner, I want my `application.yaml` validated and ingested on push, so that the registry stays in sync with the repo without forms.
- **Value:** Registry maintained where engineers already work.
- **Technical:** On `push` touching `.security/application.yaml`, fetch the file via the App, validate against `schemas/repo-contract/application.schema.json` and the active classification labels, upsert `applications` + `application_revisions` (source=application_yaml, commit SHA). Two-sided linking for secondary repos.
- **Depends on:** E06-F01, E05-F02.
- **AC:**
  - Given a valid file, when pushed to the default branch, then the app is created/updated within 5 minutes and a revision records changed fields and the commit SHA.
  - Given an invalid file, then no registry change happens, and a GitHub check run on the commit reports the schema errors (requires check-run write; until then, errors show in the platform UI).
  - Given a secondary repo claims `APP-00042` but the primary does not list it, then the link is **not** created and a mismatch is shown.
- **Security:** YAML parsed with a safe loader, size ≤ 256 KB. Declared values are C0. Owners must resolve (E03-F02).
- **Tests:** Schema tests (valid/invalid fixtures). Two-sided link tests. Idempotency (same commit twice). Fuzzing the YAML parser input.
- **Tasks:** fetcher · validator · upsert + revision · link reconciliation · error reporting.
- **Stage 1 progress:** schema + template written and validated (`schemas/repo-contract/`, `templates/repo-contract/`).

### E03-F01-S02: Onboarding PR / CLI · M · Phase 2
- **Story:** As a champion, I want a command that generates `application.yaml`, `asvs.yaml` and `aap-security.yml` for my repo, so that onboarding takes < 2 hours (PS-2).
- **Technical:** `aap onboard` CLI (Python, part of the backend package) using detection results. Opens a PR with the user's own credentials. The `aap-onboarding` App variant only if approved (ADR-005).
- **AC:** Running the CLI on a pilot repo produces schema-valid files and a PR with an explanatory description. A second run updates the PR rather than creating a new one.
- **Security:** The CLI never asks for or stores tokens beyond `gh auth`. Templates pin the workflow by SHA.
- **Tasks:** detection reuse · templating · PR creation via `gh` · docs.

## F02: Ownership verification

### E03-F02-S01: Resolve owners against Entra and GitHub · M · Phase 2
- **Story:** As Head of AppSec, I want declared owners resolved to active identities and departed owners detected, so that escalations reach real people.
- **AC:** Owners resolve to `users` rows with Entra OID and/or GitHub login. A deactivated owner flips ASC-GOV-01 to `not_satisfied` within 24h, with an explanation naming the field.
- **Depends on:** E19-F01 (Entra sync).
- **Tests:** Fixtures: active, disabled, unknown, team handle.
- **Tasks:** Graph sync · GitHub team sync · resolver · evaluator `registry_complete@1`.

## F03: Classification

### E03-F03-S01: Compute tier from the classification model · M · Phase 2
- **Story:** As an app owner, I want the tier computed transparently from my answers, so that I understand why requirements apply.
- **Technical:** Implement `config/profiles/<profile>/classification.yaml` semantics (floor rules + points). Write the `application_classifications` ledger. `GET /applications/{id}/classification` returns inputs, matched rules, points and model version.
- **AC:** Golden tests cover every floor rule and threshold boundary. The explanation text is human-readable. A changed input creates a new ledger row.
- **Tests:** Property-based tests (more critical inputs never yield a less critical tier).
- **Tasks:** engine · ledger write · API · explanation renderer.

### E03-F03-S02: Tier approval and override workflow · M · Phase 2
- **Story:** As an AppSec engineer, I want to approve Tier 1/2 classifications and any downgrade request, so that tiers cannot be lowered unilaterally (AC-09).
- **AC:** A downgrade request leaves the current tier unchanged until approved. The approver ≠ the requester and is outside the owning team. All transitions are audited.
- **Security:** SoD enforced in the policy module + DB check. Audit event `classification.decide`.
- **Tests:** SoD negative tests. AuthZ matrix rows.

## F04: Registry API

### E03-F04-S01: Applications, repositories, environments API · M · Phase 2
- **Story:** As the UI and integrations, we need CRUD-light APIs for the registry, so that views and automation can use registry data.
- **Technical:** `/applications` (list/filter/search), `/applications/{id}`, `/applications/{id}/repositories`, `/environments`, `/cloud-scopes`. Writes only for fields not owned by `application.yaml` (e.g. Jira project mapping).
- **AC:** OpenAPI documented. Cursor pagination. Allowlisted filters. Out-of-scope app → 404 (AC-03).
- **Tests:** API tests + authZ matrix + RLS integration test.
