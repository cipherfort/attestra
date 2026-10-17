# E19: Platform Security

**Goal:** The platform is the best-secured application in the estate and passes its own Tier 1 controls. Design: [platform security architecture](../../security/platform-security-architecture.md).

**Progress (Stage 9):** OIDC BFF (PKCE, `__Host-` session cookie, server-side sessions, CSRF, idle/absolute timeouts), service bearer tokens, managed-identity federated credential IMPLEMENTED and tested (in-process IdP + real OIDC server). Gap: per-process DB logins (E24-F04-S02).

## F01: Identity and access

### E19-F01-S01: Entra OIDC BFF and session management · M · Phase 1
- **AC:** Auth code + PKCE. `__Host-` cookie (HttpOnly, Secure, SameSite=Lax). 30 min idle / 8 h absolute. Server-side session store with encrypted refresh tokens. CSRF token on state-changing routes. Logout revokes the session. Conditional Access applies (the project's tenant admin sets the policy for the `aap-web` app).
- **Tests:** Session fixation, CSRF, cookie flags, expiry.

### E19-F01-S02: Policy module, RBAC + SoD, and the authZ test matrix · M · Phase 1 → every phase
- **AC:** Every route declares a permission (CI fails otherwise). Out of scope → 404. SoD rules centralised. The matrix (role × endpoint × in/out scope) runs in CI. RLS settings set per transaction.
- **Tests:** Matrix generated from the OpenAPI spec + role table. AC-03, AC-04, AC-10.

### E19-F01-S03: Entra group → role sync and PIM for platform_admin · M · Phase 1
- **AC:** Hourly sync. `platform_admin` only via PIM activation (4 h). Activation emits a SIEM event. Quarterly access-review export.

## F02: Secrets and keys

### E19-F02-S01: Key Vault integration and rotation runbooks · M · Phase 1
- **AC:** Private endpoint. Managed identities scoped per app. No secrets in Terraform state. Expiry metadata and alerts. Rotation runbooks for the App key, webhook secret, Jira/DD/DT tokens and the session key. Spike: App JWT signing via a Key Vault HSM key.

## F03: Application hardening

### E19-F03-S01: Input handling and parser hardening · M · Phase 1–5
- **AC:** Safe YAML/XML loaders. JSON depth/size limits. Zip-bomb protection. Allowlisted sort/filter fields. Problem-details errors without stack traces. Lint rule banning raw SQL strings.
- **Tests:** Fuzzing harnesses for manifest, SBOM, SARIF and YAML parsers (Atheris or Hypothesis).

### E19-F03-S02: SSRF and egress controls · M · Phase 1
- **AC:** Connectors use configured base URLs only. Webhook URLs ignored. Egress allowlist enforced at the network layer (Azure Firewall/NAT). A test confirms an attempt to reach a non-allowlisted host fails.

## F04: Assurance of the platform

### E19-F04-S01: Platform onboarded to itself (Tier 1) · M · Phase 1 → 9
- **AC:** `application.yaml` for the platform (Tier 1). `aap-security.yml` caller. All mandatory controls satisfied or excepted with approval before the pilot exit. The threat model is reviewed independently.

### E19-F04-S02: Independent penetration test of the platform · M · Phase 9
- **AC:** Scope includes the webhook receiver, BFF/API authZ, evidence forgery, RLS bypass, parser attacks and the GitHub App key handling. No open high/critical at go-live (PS-13). Findings tracked in the platform itself.
