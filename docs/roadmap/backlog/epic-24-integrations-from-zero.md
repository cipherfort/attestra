# E24: Integrations from zero (ADR-031)

**Goal:** The project creates, as code, every external system it depends on, and bootstraps the platform's least-privilege credentials in each. Nothing assumes another team.

**Progress (Stage 9, 2026-10-08):** S01–S09 IMPLEMENTED and tested locally (see each story). S10 (first real apply) and S11 (per-process DB logins) remain. Runbook: [integration bootstrap](../../operations/integration-bootstrap.md).

## F01: Infrastructure as code

### E24-F01-S01: Azure platform, Entra, Sentinel, scanners, readers as Terraform · M · Phase 1
- **AC:**
  - Every root validates against real provider schemas.
  - Checkov reports 0 failed, and every skip carries a written reason.
  - No client secrets: the API uses a managed-identity federated credential and CI uses GitHub OIDC.
  - Evidence storage is WORM (unlocked), private, has no shared keys and logs every access.
- **Status:** IMPLEMENTED (validated, not applied). `examples/terraform/azure`.

### E24-F01-S02: GitHub organization baseline and AWS reader as Terraform · M · Phase 1/8
- **Status:** IMPLEMENTED (validated). `envs/github`, `envs/aws`.

### E24-F01-S03: Platform image and release pipeline · M · Phase 1
- **AC:**
  - Base images pinned by digest; `gh` pinned by checksum.
  - The image runs as non-root with a read-only root filesystem, and refuses dev sign-in in production.
  - The release pipeline: Trivy gate → push → provenance attestation → verified before deploy → migration job → rollout.
- **Status:** IMPLEMENTED (image built and smoke-tested locally; workflow not yet run).

## F02: Bootstrap commands

### E24-F02-S01: `aap bootstrap github-app` (manifest flow) + key into Key Vault · M · Phase 1
- **AC:**
  - Read-only permissions, with no webhook locally.
  - A forged `state` is refused.
  - No secret is printed.
  - The key is imported as a non-exportable HSM key and the secret copy is deleted.
- **Status:** IMPLEMENTED, unit-tested (manifest flow with a simulated browser). Key Vault import untested without Azure.

### E24-F02-S02: `aap bootstrap dependency-track | defectdojo | jira | oidc-dev | trust-root` · M · Phase 1–8
- **AC:**
  - Idempotent where the target allows it.
  - Secrets come only from a prompt or a named environment variable, and go only to the secret store.
- **Status:** IMPLEMENTED. DT and DD tested against the real services (including re-runs and wrong passwords). Jira: contract fake + opt-in live test.

### E24-F02-S03: Local integration stack · M · Phase 1
- **AC:** `deploy/local/bootstrap.sh scanners` brings up PostgreSQL, OIDC, Azurite, Dependency-Track and DefectDojo from nothing and runs the real bootstrap commands. Generated secrets are written to 0600 files only.
- **Status:** IMPLEMENTED and run end to end, including OIDC sign-in in a browser and a DT sync from Azurite-stored evidence.

## F03: Connectors

### E24-F03-S01: Integration registry and scheduling · M · Phase 1
- **AC:**
  - `aap integrations status|run`, `GET /api/v1/integrations` and the Integrations page.
  - Unconfigured integrations are never scheduled.
  - Every run is recorded (`ok | partial | failed`, gaps).
- **Status:** IMPLEMENTED.

### E24-F03-S02: Real connectors · M · Phase 1–8
- **Scope:** GitHub App + settings, Sigstore (two backends), OIDC BFF, Jira, Dependency-Track, DefectDojo, Defender, Security Hub, Sentinel, Azure Blob.
- **Status:** IMPLEMENTED. The test target for each is in [ADR-031 section 4](../../../adr/ADR-031-integrations-owned-and-bootstrapped-by-the-project.md#decision).

## F04: Remaining

### E24-F04-S01: First apply in a real tenant / organization / site · M · Phase 1
- **AC:**
  - Runbook steps 1–12 completed.
  - `aap integrations status` shows everything in scope as configured, and each connector's first run is `ok` or explains its gaps.
  - The WORM policy is verified by a failed delete attempt.
  - The AWS trust claims (`iss`/`aud`/`sub`) are confirmed on a real token.
- **Depends on:** the accounts in runbook section 0 and decision D-018.

### E24-F04-S02: Per-process PostgreSQL logins (risk R-25) · M · before pilot
- **AC:**
  - `aap_api_login`, `aap_worker_login` and `aap_hook_login` are each granted only their role. Entra authentication to PostgreSQL for the managed identities.
  - The admin password is used only by the migration job.

### E24-F04-S03: Role-assignment admin (scoped Entra groups → platform roles) · S · Phase 7
- **AC:** A platform admin maps an app-assigned Entra group to a scoped role through the API, with audit and two-person approval for org-wide grants. (Today this is a direct database statement.)

### E24-F04-S04: azurerm 5.x upgrade · C · after first deployment

### E24-F04-S05: Controlled egress (NAT Gateway + Azure Firewall FQDN allowlist, ADR-025) · M · before pilot
- **AC:** All outbound traffic from the Container Apps subnet goes through the firewall. The allowlist covers GitHub, Jira, FIRST/EPSS, CISA, OSV/NVD, AWS STS/Security Hub, Entra and the Azure endpoints. Anything else is denied and logged.
