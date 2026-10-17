# ADR-015: Secrets management

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-014, the Key Vault pattern from the earlier prototype

## Context

Remaining secrets after federation: the GitHub App private key(s), the GitHub webhook secret, Jira credentials, DefectDojo and Dependency-Track API keys, the session encryption key and the evidence-checkpoint signing key (if used).

## Decision

- **Azure Key Vault** (RBAC mode, purge protection, soft delete 90 days, **private endpoint, public network access disabled**), one vault per environment, separate from the DD/DT vault.
- **Premium SKU (HSM-backed keys) PROPOSED** for the GitHub App key (*key*, not secret) if GitHub App JWT signing can be done via Key Vault `sign` so the private key never leaves the HSM. Feasible because the App JWT is an RS256 signature. **Spike in Phase 1.**
- Access by **managed identity** with per-secret scoping where possible. `aap-hook` can read only the webhook secret. `aap-worker` can read connector secrets. `aap-web` can read the session key.
- Container Apps secrets reference Key Vault (no values in Terraform state beyond what the provider requires). Note: the existing infra pattern generates secrets with `random_password`, which puts them in state. The new platform **does not**. Secrets are created out-of-band or by a bootstrap script, and only referenced in Terraform.
- **Rotation:** GitHub App key 90 days (two keys overlap during rotation), webhook secret 180 days, Jira/DD/DT tokens 90 days, session key 365 days (keyring with the previous key accepted for decryption). Expiry metadata is set on every secret and an alert fires 14 days before.
- **Never in logs:** a structured-logging redaction filter, plus a test that greps logs from the integration test run for known secret values.

## Alternatives considered

| Option | Why not |
|---|---|
| HashiCorp Vault | Capable, but another platform to run. Key Vault is the organisational standard on Azure. |
| Container Apps inline secrets | No central audit or rotation. Values end up in IaC state. |
| Terraform `random_password` → Key Vault (infra-repo pattern) | Secret material in Terraform state. Acceptable for an MVP, not for this platform. |

## Decision drivers

Federation first · no secrets in state or env files · auditable access · rotation.

## Consequences

Bootstrap requires a privileged one-off step per environment (runbook). Rotation is partly manual until automated (backlog E19).

## Security implications

Key Vault diagnostic logs → Log Analytics → Sentinel. An analytics rule fires on access from an unexpected identity.

## Operational implications

Rotation runbooks. Expiry alerts. Break-glass procedure for Key Vault access via PIM.
