# E06: GitHub Integration

**Goal:** Reliable, least-privilege, read-only integration with GitHub as the primary evidence source.

**Progress (Stage 9):** App token minting (Key Vault signing), settings connector (`repo.*`, `registry.application`, `repo.threat_model`, `scan.secrets` + secret findings), Sigstore attestation verification, `aap bootstrap github-app` IMPLEMENTED and tested (recorded API shapes; real attestation bundle). Creating the App in a real organization is runbook step 7.

## F01: GitHub App and webhook receiver

### E06-F01-S01: `aap-reader` GitHub App · M · Phase 1
- **Story:** As the platform, I need a read-only GitHub App installed org-wide, so that I can read repos, runs, settings and alerts without user tokens.
- **Technical:** App manifest with the permissions in ADR-005. Private key in Key Vault. Installation-token cache (≤ 55 min). Spike: sign the App JWT via Key Vault `sign` (HSM key).
- **Depends on:** `aap bootstrap github-app` (IMPLEMENTED) run by the project's org owner. E19-F02 (Key Vault).
- **AC:** The installation token works for all in-scope repos. Any write API call fails (verified in a test). Key rotation runbook tested with 2 overlapping keys.
- **Security:** No write permissions. IP allow list on the App if available. Token never logged.
- **Tests:** Integration test against a sandbox org. Permission-negative test (attempt to create an issue → 403).
- **Tasks:** manifest · Key Vault integration · token cache · rotation runbook.

### E06-F01-S02: Webhook receiver (`aap-hook`) · M · Phase 1
- **Story:** As the platform, I need a minimal internet-facing receiver that authenticates GitHub webhooks and enqueues work, so that events arrive promptly without exposing data paths.
- **Technical:** Separate deployable. HMAC-SHA256 verify (constant time). Delivery-ID replay cache (`webhook_deliveries`, 24h). Enqueue `{event, delivery_id, repo_id, ids}`. Returns 202. Body ≤ 25 MB (GitHub max). Ingress IP restriction to GitHub `hooks` ranges.
- **AC:** Bad HMAC → 401 and no enqueue (AC-06). Replay → 200 and no second job. p99 < 200 ms. The receiver identity has no DB read beyond its two tables.
- **Security:** No payload content trusted beyond IDs. No outbound calls.
- **Tests:** Signature tests (valid, invalid, missing, wrong algorithm). Replay. Load test at 50 rps.

## F02: Sync and reconciliation

### E06-F02-S01: Repository, settings and rules sync · M · Phase 2
- **Story:** As the evaluator, I need current repo settings (rulesets via "rules for a branch", security settings, CODEOWNERS errors, environments, collaborators, secret names, Actions policy), so that configuration controls can be evaluated.
- **AC:** Each produces C1 evidence of the matching type with `continuous` freshness. Changes via webhook reflect within 5 min. Reconciliation catches a missed webhook within 6h.
- **Tests:** Fixture-based tests per endpoint. ETag conditional requests verified.

### E06-F02-S02: GHAS alerts sync (code scanning, secret scanning, Dependabot) · M · Phase 5
- **Story:** As the platform, I want GHAS alerts as findings and C3 evidence, so that native GitHub results count without pipeline changes.
- **AC:** Alerts map to findings with stable fingerprints (alert number). Secret values are never fetched or stored (the API option to hide secrets is used). Alert state changes are reflected. Dismissals are recorded as *suppressions* (ADR-021).
- **Security:** Secret-scanning endpoints accessed with `hide_secret=true` (or equivalent). Redaction test.

### E06-F02-S03: Workflow run and artifact retrieval · M · Phase 1
- **Story:** As the ingestion worker, I need run metadata (`referenced_workflows`, `head_sha`, event, conclusion) and artifact download, so that evidence can be verified.
- **AC:** Artifacts > 200 MB or decompression ratio > 100 are aborted (AC-07). Downloads stream to a temporary file with a hash computed on the fly.
- **Tests:** Zip-bomb fixture. Truncated download. Expired artifact.

## F03: Rate limits and resilience

### E06-F03-S01: Rate-limit-aware client · M · Phase 2
- **Story:** As the platform, I need a GitHub client that respects primary and secondary rate limits, so that sync never gets the App blocked.
- **AC:** Honours `Retry-After`/`x-ratelimit-reset`. Exponential backoff. Per-installation budget metrics. Concurrency cap per installation.
- **Tests:** Simulated 403/429 secondary-limit responses.
