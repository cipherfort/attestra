# Test Strategy: FortProof

| | |
|---|---|
| Status | IMPLEMENTED: unit, PostgreSQL integration, database security-property, API contract (Schemathesis), parser fuzzing (Hypothesis) and Helm install/upgrade tests, all in CI |
| Owner | Platform tech lead |
| Backlog | [E22](../roadmap/backlog/epic-22-testing.md) |

## 1. Priorities

The platform's credibility rests on three properties, which get the heaviest testing:
1. **Evaluations are correct.** No control is reported satisfied without valid evidence.
2. **Evidence is trustworthy.** It cannot be forged, altered or deleted undetectably.
3. **Access is correctly scoped.** No cross-unit leakage, and SoD holds.

## 2. Test levels

| Level | What it checks | Tooling | When |
|---|---|---|---|
| Static | Lint and strict types; catalogue, config, schema and metrics validation; generated reference pages current; links; the shipped pipelines and this repository's workflows (actionlint, zizmor); the licence gate; Terraform format, validation and Checkov | ruff, mypy, `tools/*` validators, actionlint, zizmor, Checkov | Every pull request |
| Unit | Evaluators, freshness, risk model, classification, fingerprints, parsers, policy module | pytest, Hypothesis (property-based) | Every pull request |
| Database | Security properties of the schema (append-only ledgers, SoD, RLS, partitions) and upgrades from every earlier migration, with data | `tests/database/run.sh`, pytest on PostgreSQL 16 | Every pull request |
| Integration | Repository layer and RLS, the job queue, connectors against recorded API shapes and fakes (moto, respx), the demo world end to end | pytest on PostgreSQL 16 | Every pull request |
| API contract | The OpenAPI document matches the implementation in both directions; generated requests, including malformed ones, against every implemented read operation | alignment test, Schemathesis | Every pull request |
| Browser | Every page and role in a browser against the real API and its Content Security Policy; WCAG 2.2 AA in both themes (axe); keyboard paths; reduced motion; the bundle-size budget | Playwright, axe-core | Every pull request |
| Packaging | The container image runs as non-root with a read-only root filesystem; the Helm chart lints, validates (Kubernetes 1.27 and 1.31) and installs and upgrades on kind; the docs site builds | Docker, Helm, kubeconform, kind, MkDocs | Every pull request |
| Supply chain | Code scanning, secrets in the full history, dependency updates, OpenSSF Scorecard; releases signed with SBOM and provenance | CodeQL, gitleaks, Dependabot, Scorecard, cosign | Every pull request, weekly, each release |
| Fuzzing | Every parser of untrusted input, 5,000 examples each | Hypothesis (`fuzz` profile) | Nightly |
| Live services | GitLab CE end to end with a real runner; opt-in tests against Dependency-Track, DefectDojo, an OIDC provider and Azurite | pytest | Nightly (GitLab), opt-in |
| Disaster recovery | Restore drill | [Backup plan section 3](../operations/backup-and-restore-plan.md#3-restore-drill) | Every 6 months (operators) |
| Planned | An independent penetration test before 1.0, then yearly; load tests at the [design scale](../architecture/02-platform-architecture.md#7-scale-envelope-design-target); fault injection (upstream outages, worker crashes); DAST against a deployed instance | External, k6, toxiproxy, ZAP | Before 1.0 |

## 3. Key test suites

### 3.1 Evaluator correctness
For every activity control: **"configuration present, never executed → NO_EVIDENCE"**. For every evaluator: satisfied, not satisfied, stale, partial, N/A and error cases. Explanation text snapshot tests. Calibration (production): a 5% quarterly manual sample (EVD-04).

### 3.2 Evidence integrity (abuse cases)
| Case | Expected |
|---|---|
| AC-01 hand-crafted manifest from own workflow | `UNTRUSTED_PRODUCER` |
| AC-02 approved path at an unapproved SHA | `UNAPPROVED_WORKFLOW_REF` |
| Digest mismatch between manifest and raw | `DIGEST_MISMATCH` |
| Manifest commit ≠ run head SHA | `BINDING_MISMATCH` |
| Zip bomb / oversize artifact (AC-07) | `REJECTED_SIZE` |
| AC-05 superuser UPDATE with trigger disabled | Detected by chain verification |
| Blob overwrite / delete | Denied by WORM |
| Replay of the same run | Idempotent (no duplicate evidence) |

### 3.3 Access control
Every operation declares `x-permission` (checked in CI) · out-of-scope → 404 (AC-03) · SoD (AC-04) · export restrictions (AC-10) · RLS-level tests T5–T9 plus API-level tests for every persona of the demo world.

### 3.4 Deduplication and lifecycle
10 identical pipeline runs → 0 new findings and 0 new tickets (PS-6) · concurrent workers on the same dedup key → one ticket · Jira Done without a fix → reopened (PS-7) · regression → reopened finding.

### 3.5 Supply chain of the platform
Unpinned action → CI fail (zizmor) · every release image is signed (cosign) and carries an SBOM and build provenance; verify both before deploying (the commands are in each release's notes).

## 4. Test data

Synthetic only: generated orgs, repos, apps, findings and SBOMs (no production data in non-prod). Recorded API fixtures are scrubbed of tokens and personal data before commit (pre-commit secret scan).

## 5. Environments

Local (docker compose: PG, Azurite, stub connectors) · CI (ephemeral containers) · dev (Azure, sandbox GitHub org, Jira sandbox) · prod.
