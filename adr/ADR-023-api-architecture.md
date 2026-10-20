# ADR-023: API architecture and implementation stack

**Status:** Accepted (2026-10-20), implemented  ·  **Related:** ADR-013, ADR-014, ADR-024

## Context

The platform is API-first. The UI, reporting integrations and automation all use the same API. The team's existing automation is Python and Terraform. The workload is I/O-bound integration and relational queries.

## Decision

**API style:** **REST**, contract-first **OpenAPI 3.1** (`schemas/api/openapi.yaml`, Stage 2). Generated TypeScript client for the UI. Generated docs.

| Concern | Convention |
|---|---|
| Versioning | URL major version `/api/v1`. Additive changes only within a major. Deprecations announced with `Deprecation` and `Sunset` headers, ≥ 6 months. |
| Resources | `/applications`, `/applications/{id}/controls`, `/applications/{id}/evidence`, `/findings`, `/vulnerabilities/{id}/affected-applications`, `/sboms`, `/components`, `/exceptions`, `/assessments`, `/maturity`, `/asvs`, `/threat-models`, `/tickets`, `/teams`, `/users/me`, `/reports` |
| Pagination | Cursor-based (`?cursor=…&limit=…`, max 200). `next` link in the response. |
| Filtering/sorting | Allowlisted fields only: `?filter[priority]=P1,P2&filter[status]=open&sort=-sla_due_at` |
| Errors | **RFC 9457** `application/problem+json` with stable `type` URIs and a `request_id` |
| Concurrency | `ETag` / `If-Match` on mutable workflow objects (exceptions, assessments) |
| Idempotency | `Idempotency-Key` header on POSTs that create workflow objects |
| Long operations | 202 + job resource (e.g. report generation, CVE impact export) |
| Rate limits | `RateLimit-*` headers. 429 with `Retry-After`. |
| AuthZ | Every operation annotated with a permission. CI fails if missing (ADR-013). |

**Implementation stack:**
- **Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (async), Alembic.** One package `aap` with entrypoints `web`, `hook`, `worker`. Typed (`mypy --strict` on domain modules). `uv` for locked dependencies.
- **Frontend:** **React + TypeScript (Vite)**, TanStack Query, a component library with accessible defaults (WCAG 2.2 AA target), charts per the organisation's data-viz palette. Served as static assets by the BFF.

## Alternatives considered

| Option | Why not |
|---|---|
| GraphQL | Flexible for dashboards. But field-level authZ, query-cost DoS controls and caching add security surface, and the team has no GraphQL experience. REST + purpose-built aggregate endpoints is sufficient. |
| gRPC | No browser need. Internal only. Not justified. |
| Go backend | Faster and statically typed. But the team's skills and the integration ecosystem (parsers, SDKs) favour Python. Performance is not the bottleneck. |
| TypeScript/NestJS backend | One language end to end. Weaker for the data/parsing work. Splits from existing Python automation. |
| Next.js SSR | Adds a Node server tier. BFF in FastAPI covers sessions. Static SPA is simpler to secure (strict CSP). |

## Decision drivers

Security of the API surface · team skills · contract-first clients · simplicity.

## Consequences

Aggregate endpoints for dashboards (e.g. `/reports/org-scorecard`) are designed deliberately rather than relying on clients composing many calls.

## Security implications

Allowlisted filters prevent injection via sort/filter. Problem details never include stack traces. Response models are explicit (no ORM object leakage).

## Operational implications

The OpenAPI spec is linted (Spectral) in CI. Breaking-change detection (oasdiff) runs against the last release.
