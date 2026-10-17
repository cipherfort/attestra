# E22: Testing

**Goal:** A test strategy that proves the platform is correct, secure and resilient, with particular weight on evidence integrity and access control.

## F01: Test strategy and pyramid

### E22-F01-S01: Test strategy document and CI wiring · M · Phase 1
- **AC:** Strategy covers unit, integration (Testcontainers PG), API contract (Schemathesis against our own OpenAPI), end-to-end (sandbox GitHub org + canary repos + sandbox Jira), security, performance, resilience/failure, access control, evidence integrity, and supply chain. Coverage gates as in the DoD. Flaky-test policy.

## F02: Security testing

### E22-F02-S01: Abuse-case suite (AC-01 … AC-10) · M · Phase 1 → 5
- **AC:** Each abuse case from the [platform threat model §5](../../security/platform-security-architecture.md#5-abuse-cases-drive-security-tests) is an automated test in CI with the expected outcome. A failure blocks merge.

### E22-F02-S02: Access-control matrix tests · M · Phase 1 →
- **AC:** Generated from roles × OpenAPI operations × scope. Includes RLS-level tests (as in `tests/database/test_schema_security.sql` T5–T9) and API-level tests. 404-not-403 verified.

### E22-F02-S03: Evidence-integrity tests · M · Phase 4
- **AC:** Tamper tests: trigger-disabled superuser UPDATE detected by chain verification. Blob overwrite rejected by WORM. Manifest/artifact digest mismatch rejected. Replayed evidence (same run) idempotent. Evidence from a retired SHA after the window rejected.
- **Stage 1 progress:** ledger immutability, SoD, closure-requires-evidence and RLS properties IMPLEMENTED as DB tests (12 passing).

### E22-F02-S04: Supply-chain tests · S · Phase 3
- **AC:** CI fails on unpinned third-party actions (zizmor), new dependencies without lockfile updates, or images not pinned by digest. SBOM generated and attested for every platform build. `gh attestation verify` in CD tested with a deliberately unattested image (must fail).

## F03: Non-functional testing

### E22-F03-S01: Performance and scale tests · S · Phase 5–9
- **AC:** At design scale (2,000 apps, 10,000 repos, 2M components, 20M evidence rows): CVE impact query < 5 s p95, scorecard API < 500 ms p95, webhook receiver 50 rps with p99 < 200 ms, ingestion p95 < 10 min under a weekly scheduled-scan burst.

### E22-F03-S02: Resilience and failure tests · S · Phase 8–9
- **AC:** GitHub API 5xx/rate limit, Jira down, DD/DT down, PG failover, worker crash mid-job: no evidence loss, no duplicate tickets, states turn `error` (not `satisfied`) when inputs are unavailable, recovery via reconciliation verified.
