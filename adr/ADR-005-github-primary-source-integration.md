# ADR-005: GitHub as primary source integration (GitHub App, pull-based evidence)

**Status:** Proposed (2026-10-07), amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Amends (historical reference):** the earlier prototype's ADR-0001 (ingestion path)  ·  **Related:** [Platform architecture section 5.1](../docs/architecture/02-platform-architecture.md#51-pipeline-evidence-primary-path-pull-based), [Evidence model section 4](../docs/architecture/04-evidence-model.md#4-producer-verification)

## Context

Source, pipelines and GHAS findings live in GitHub Enterprise Cloud. The existing pilot has pipelines *push* results to Dependency-Track and DefectDojo using **API keys stored in every onboarded repo** (current-state issue CS-1). Anyone with write access to any onboarded repo can exfiltrate a key with platform-wide rights.

## Decision

1. Integrate through a **GitHub App `aap-reader`**, installed org-wide, with **read-only** permissions:
   - Repository: Metadata, Contents, Actions, Administration (rulesets, branch protection, collaborators), Checks, Code scanning alerts, Dependabot alerts, Secret scanning alerts, Deployments, Environments, Pull requests, Secrets (**names only**, as the API never returns values), Attestations.
   - Organisation: Members, Administration (org rulesets, Actions policy), Custom properties.
   - **No write permission of any kind.**
2. **Webhooks** (`workflow_run`, `push`, `repository`, `repository_ruleset`, `branch_protection_rule`, `security_and_analysis`, `code_scanning_alert`, `secret_scanning_alert`, `dependabot_alert`, `deployment_status`, `installation_repositories`) go to the isolated **webhook receiver**. The payload is a *hint*: workers re-fetch state from the API.
3. **Evidence is pulled.** On `workflow_run.completed`, a worker downloads the evidence artifact, verifies it (approved workflow SHA, attestation, digests, binding) and stores it. **Consumer repos hold no platform credentials.**
4. A periodic **reconciliation** (every 6h, staggered) catches missed webhooks.
5. **Write operations** (onboarding PRs, setting a repo custom property `aap_tier` used for ruleset targeting) need a separate **`aap-onboarding` App** with `contents:write`, `pull_requests:write` and org `custom_properties:write`, isolated in its own worker identity and Key Vault key. **REQUIRES HUMAN APPROVAL.** Until approved, onboarding PRs are opened by teams using a CLI/template. The pilot does not depend on it.

## Alternatives considered

| Option | Why not |
|---|---|
| Push from CI with platform API keys (status quo) | CS-1: credential sprawl and forgeable evidence. |
| Push from CI with GitHub OIDC tokens to a platform ingest API | No stored secrets, and the OIDC claims (`job_workflow_ref`) are verifiable. But it needs an internet-facing ingest endpoint with a read/write path, and trusts the pipeline's account of results. **Kept as a fallback** for runners that cannot produce artifacts. |
| Personal access tokens / OAuth app | Tied to a person. Coarse scopes. Not appropriate. |
| GitHub audit-log streaming only | Good for configuration *changes*, not run results or alert state. Considered later as an additional C1 source. |

## Decision drivers

No secrets in consumer repos · independent verification · least privilege · resilience to missed events.

## Consequences

- One App installation covers all repos. Its private key is the platform's most sensitive credential (threat T-10).
- Rate limits: an App installation has higher limits than a user token, and scales with org size. Reconciliation is staggered and uses conditional requests (ETags).
- The infra repo's per-repo DD/DT secrets are retired in Phase 3 ([pipeline migration](../docs/architecture/05-pipeline-architecture.md#7-migration-from-the-existing-reusable-workflows)).

## Security implications

- Read-only scope means a stolen `aap-reader` key can read code and alerts but **cannot modify any repository**.
- Mitigations: key imported into Key Vault as a non-exportable HSM key and used for signing there (IMPLEMENTED: `aap bootstrap github-app-key-to-keyvault`, `KeyVaultSigner`), 90-day rotation, the GitHub App IP allow list (Enterprise feature; decision D-018), alerting on token use from unexpected IPs via GitHub audit log → Sentinel.
- `aap-onboarding`, if approved, can push branches and open PRs but **cannot merge** to protected default branches, because org rulesets require review.

## Operational implications

The project's organization owner creates the App with `aap bootstrap github-app` (manifest flow, one click) and installs it (ADR-031, runbook step 7). Webhook secret rotation. Monitoring of webhook delivery failures (GitHub redelivery API used by reconciliation).
