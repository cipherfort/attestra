# Secure Architecture Standard

| | |
|---|---|
| ID | STD-05 · Status: Template. Adapt it and have it approved in your organization. |
| Owner | AppSec lead, with Enterprise Architecture |
| Related | SAMM Secure Architecture (D-SA) and Architecture Assessment (V-AA) |

## 1. Purpose

Sets the security principles, reference patterns and review obligations for application architecture.

## 2. Architecture principles

| ID | Principle | Expectation |
|---|---|---|
| ARC-P1 | Centralised identity | Workforce authentication via the organization's identity provider (OIDC or SAML). Customer authentication via the approved customer identity provider. **No local password stores** without an exception. |
| ARC-P2 | Least privilege | Managed identities and workload identity federation over keys. Scoped roles. No standing admin. |
| ARC-P3 | Secrets in vaults | A managed secret store (for example Azure Key Vault, AWS Secrets Manager or HashiCorp Vault) accessed by workload identity. Never in code, IaC variables or app settings. (ASC-DEP-04) |
| ARC-P4 | Private by default | Data services on private endpoints. Internet exposure only through an approved edge (WAF). |
| ARC-P5 | Defence in depth for authorisation | Server-side authorisation on every request, object-level checks, deny by default |
| ARC-P6 | Secure defaults | Security headers, TLS 1.2+, safe parsers, framework protections enabled |
| ARC-P7 | Observable | Security events logged to the SIEM with the application ID (ASC-OPS-01) |
| ARC-P8 | Supported technology | Only supported runtimes/frameworks. No end-of-life components. (ASC-ARC-02) |
| ARC-P9 | Data minimisation | Collect, retain and replicate only what is necessary. Data stores declared in `application.yaml`. (ASC-OPS-05) |

## 3. Reference architectures (to be published as patterns, E21)

Web application behind a WAF · internal API protected by identity-provider app roles · event-driven worker with workload identity · a hardened container workload baseline · CI/CD with OIDC deployment.

## 4. Requirements

| ID | Requirement | Proven by |
|---|---|---|
| SAR-01 | Tier 1/2 applications shall have an architecture security review before first production release and after every material change | ASC-ARC-01 (M2) |
| SAR-02 | Review findings shall be recorded in the platform and remediated within SLA | ASC-ARC-03 |
| SAR-03 | Deviations from ARC-P1–P9 shall be recorded as exceptions | Exception workflow |
| SAR-04 | No end-of-life runtime, framework or OS in current SBOMs or deployed images | ASC-ARC-02 |
| SAR-05 | Material changes are: new external interface, new trust boundary, new data store or data classification, change of authentication model, new privileged integration, or move to a different hosting model | Event-bound freshness on reviews |

## 5. Review process

Request in the platform → AppSec reviewer assigned (independent of the team) → inputs: threat model, architecture docs at a commit SHA → review against principles + threat model → outcome `approved` / `approved_with_conditions` / `rejected` → findings recorded → evidence `assessment.architecture_review` (M2).
