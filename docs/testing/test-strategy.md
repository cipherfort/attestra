# Test Strategy: Attestra

| | |
|---|---|
| Status | IMPLEMENTED: unit, PostgreSQL integration, database security-property, API contract (Schemathesis), parser fuzzing (Hypothesis) and Helm install/upgrade tests, all in CI |
| Owner | Platform tech lead |
| Backlog | [E22](../roadmap/backlog/epic-22-testing.md) |

## 1. Priorities

The platform's credibility rests on three properties, which get the heaviest testing:
1. **Evaluations are correct.** No control is reported satisfied without valid evidence.
2. **Evidence is trustworthy.** It cannot be forged, altered or deleted undetectably.
3. **Access is correctly scoped.** No cross-directorate leakage, and SoD holds.

## 2. Test levels

| Level | Scope | Tooling | Runs | Gate |
|---|---|---|---|---|
| Static | Lint, types, catalogue/config/schema/OpenAPI validation, link check | ruff, mypy (strict, whole backend), `tools/*` validators, Spectral, oasdiff | Every PR | Blocking |
| Unit | Evaluators, freshness policies, risk model, classification, fingerprints, parsers, policy module | pytest + Hypothesis (property-based) | Every PR | Blocking, coverage ≥ 85% on `domain/`, `evaluators/`, `risk/` |
| Database | DDL security properties (ledgers, SoD, RLS, partitions), migrations up/down | `tests/database/run.sh`, Testcontainers | Every PR touching schema | Blocking |
| Integration | Repository layer + RLS, queue semantics, connectors against recorded fixtures (VCR) and stub servers | pytest, Testcontainers PG, WireMock-style stubs | Every PR | Blocking |
| API contract | Implementation conforms to OpenAPI. Negative cases generated. | Schemathesis against `schemas/api/openapi.yaml` | Every PR (smoke), nightly (full) | Blocking (smoke) |
| End-to-end | Sandbox GitHub org with canary repos → `security-workflows` → ingestion → evaluation → Jira sandbox → re-scan closure | Playwright (UI), scripted scenarios | Nightly + pre-release | Release gate |
| Security | Abuse cases AC-01…AC-10, authZ matrix, SAST/SCA/secrets/container/IaC on the platform, DAST (ZAP) on dev, parser fuzzing | pytest, ZAP, Atheris/Hypothesis | PR (abuse cases, authZ), nightly (DAST, fuzz) | Blocking (PR set) |
| Penetration test | Independent, full scope ([E19-F04-S02](../roadmap/backlog/epic-19-platform-security.md)) | External | Before 1.0, then annually | Go-live gate |
| Performance | Design scale ([architecture section 7](../architecture/02-platform-architecture.md#7-scale-envelope-design-target)) | k6/Locust, synthetic data generator | Pre-release, monthly | Release gate for listed SLOs |
| Resilience / failure | Upstream outages, rate limits, PG failover, worker crash mid-job, poison messages | Fault injection (toxiproxy), chaos scripts | Pre-release | Release gate |
| DR | Restore drill | [Backup plan section 4](../operations/backup-and-restore-plan.md#4-restore-drill) | 6-monthly | Operational gate |

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
Matrix generated from OpenAPI `x-permission` × roles × (in-scope, out-of-scope): out-of-scope → 404 (AC-03) · SoD (AC-04) · export restrictions (AC-10) · RLS-level tests T5–T9 plus API-level equivalents · executive role cannot reach finding detail.

### 3.4 Deduplication and lifecycle
10 identical pipeline runs → 0 new findings and 0 new tickets (PS-6) · concurrent workers on the same dedup key → one ticket · Jira Done without a fix → reopened (PS-7) · regression → reopened finding.

### 3.5 Supply chain of the platform
Unpinned action → CI fail (zizmor) · unattested image → CD refuses (`gh attestation verify` negative test) · SBOM generated and attested per build.

## 4. Test data

Synthetic only: generated orgs, repos, apps, findings and SBOMs (no production data in non-prod). Recorded API fixtures are scrubbed of tokens and personal data before commit (pre-commit secret scan).

## 5. Environments

Local (docker compose: PG, Azurite, stub connectors) · CI (ephemeral containers) · dev (Azure, sandbox GitHub org, Jira sandbox) · prod.
