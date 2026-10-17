# Trust boundaries: Claims API

| ID | Boundary | What crosses it | Controls at the boundary |
|---|---|---|---|
| TB-01 → TB-02 | Internet → application | Customer requests, uploads | WAF, OIDC token validation, rate limiting, input validation, upload size/type limits |
| TB-02 → TB-03 | Application → data tier | Claim records, documents | Managed identity, private endpoints, least-privilege DB roles, encryption at rest |
| TB-02 → TB-04 | Application → third party | Email address, claim reference | Minimised payload, API key in Key Vault, TLS |
| Caseworker UI → TB-02 | Corporate → application | Case decisions | Entra ID + Conditional Access, role-based authorisation |
