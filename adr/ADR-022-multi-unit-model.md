# ADR-022: Multi-unit (multi-tenancy) model

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-013, ADR-008, schema tests T5–T8

## Context

One organisation, several business units, many teams. Business units should not routinely see each other's vulnerability detail. Security leadership needs organisation-wide views. Teams move between business units.

## Decision

- **Single deployment, logical isolation.** `org_units` hierarchy (organisation → business unit → team). Applications belong to a team.
- Visibility = the caller's org units expanded to descendants (computed by the API from role assignments and team membership) **plus** org-wide roles.
- Enforcement in the **API policy module**, backed by **PostgreSQL RLS** keyed on the application's *current* org unit (history follows the app when it moves).
- Org-wide aggregates (maturity distributions, coverage) are visible to business unit leads as **anonymised comparisons** ("your business unit vs organisation median"), without other business units' app names, unless policy decides otherwise (REQUIRES HUMAN APPROVAL: transparency vs sensitivity).
- Configuration (catalogue, risk model, tiers) is **organisation-wide**. Business units cannot fork controls. Per-business unit SLA variance is not supported (deliberately).

## Alternatives considered

| Option | Why not |
|---|---|
| Deployment per business unit | Breaks org-wide views and CVE queries. N× operations. |
| Schema per business unit | Complex migrations. Cross-unit queries awkward. |
| No isolation (everyone sees everything) | Over-exposure of exploitable weakness data. Fails least privilege. |

## Decision drivers

Org-wide CVE response · least privilege · operational simplicity.

## Consequences

Correctness of org-unit assignment matters (sync from Entra/GitHub with drift alerts). App moves need a lead's approval.

## Security implications

RLS fails closed (T6). Partition bypass is closed (T8). The authZ test matrix covers cross-unit access.

## Operational implications

The org hierarchy is maintained from an authoritative source (HR/Entra groups). Mapping errors surface in an admin report.
