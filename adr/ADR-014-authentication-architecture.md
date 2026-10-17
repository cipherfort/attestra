# ADR-014: Authentication architecture

**Status:** Proposed (2026-10-07), amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** ADR-013, ADR-015

## Context

Human users authenticate with the enterprise IdP (Entra ID, assumption A-02). Service integrations (reporting tools, future automation) need API access. Inbound webhooks come from GitHub (and optionally Jira). Outbound calls go to GitHub, Jira, Azure, AWS, DD and DT.

## Decision

| Flow | Mechanism |
|---|---|
| **Browser users** | Entra ID **OIDC authorization code + PKCE via a backend-for-frontend (BFF)**. Tokens stay server-side. The browser holds an opaque `__Host-` session cookie (`HttpOnly; Secure; SameSite=Lax`). 30-min idle, 8-h absolute. Conditional Access (MFA, compliant device) applies to the app registration. |
| **Service clients → API** | Entra **client credentials** with **app roles** (e.g. `Reports.Read`). JWT validated (issuer, audience, signature via JWKS, `exp/nbf`, app role). **No static API keys.** |
| **GitHub webhooks → receiver** | HMAC-SHA256 signature, constant-time compare, delivery-ID replay cache, source IP restricted to GitHub `hooks` ranges |
| **Jira webhooks → receiver** (optional) | Jira Cloud: JWT-signed webhooks via an app (preferred) or shared secret in the URL path. Treated as hints only. |
| **Platform → Azure** (PG, Blob, KV, Resource Graph, Log Analytics) | **Managed identity** |
| **Platform → GitHub** | GitHub App JWT → installation token (1h) |
| **Platform → AWS** | **Web identity federation**: an Entra token for the platform's managed identity is exchanged via `AssumeRoleWithWebIdentity` for a read-only role. **No AWS access keys.** (IAM OIDC provider + role created by the project, `examples/terraform/azure/envs/aws`, ADR-031.) |
| **Platform → Jira / DD / DT** | Service account tokens in Key Vault (ADR-015). Rotated. |
| **CI fallback push** (ADR-005 alternative) | GitHub Actions OIDC JWT with `aud=aap`. Claims checked: `repository_id`, `job_workflow_ref` ∈ trusted producers. |

## Alternatives considered

| Option | Why not |
|---|---|
| SPA with MSAL, access tokens in browser | Token theft via XSS has larger impact. The current OAuth browser-app guidance favours BFF for sensitive apps. |
| API keys for integrations | Long-lived and shareable. Rejected by principle. |
| Local accounts | Rejected. |

## Decision drivers

No long-lived credentials where federation exists · tokens kept out of the browser · enterprise Conditional Access applies.

## Consequences

The BFF holds sessions, so session storage is in PostgreSQL (encrypted refresh tokens, key in Key Vault) to allow multiple replicas.

## Security implications

CSRF protection is required on BFF routes (SameSite + double-submit token). Logout revokes the session server-side.

## Operational implications

App registrations, app roles, Conditional Access policy and AWS IAM federation are external setup tasks (IAM / cloud teams).
