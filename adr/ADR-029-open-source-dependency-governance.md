# ADR-029: Open-source dependency governance

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-028, [`config/licence-policy.yaml`](../config/licence-policy.yaml), controls ASC-BLD-07/08/09

## Context

Applications depend on thousands of open-source packages. Risks: known vulnerabilities, malicious/typosquatted or hijacked packages, abandoned projects, incompatible licences.

## Decision

1. **Licence policy** (allow / review / deny by SPDX ID, distribution-context aware) in versioned config, evaluated centrally on SBOM ingest (ASC-BLD-08). Deny requires a legal exception. **Content REQUIRES Legal approval.**
2. **New dependency criteria** (enforced as guidance at PR via dependency review, measured by platform reporting):
   - not on malicious-package advisories (hard block, ASC-BLD-09);
   - maintained (a release or commit in the last 12 months) unless justified;
   - OpenSSF Scorecard score shown in the PR summary (informational, PROPOSED);
   - licence allowed for the app's distribution model.
3. **Cooldown:** automated update tools wait **3 days** after a release before proposing non-security upgrades (Renovate `minimumReleaseAge` / equivalent). Most malicious releases are detected and pulled within that window. Security fixes bypass the cooldown.
4. **Package proxy** (Azure Artifacts upstream sources or equivalent): PROPOSED for Phase 11. It enables central blocking of known-bad versions and resilience to registry outages. Not a prerequisite.
5. **Malicious package response:** P1, no exception, SOC event, and CI runner and secret compromise assessment (ADR-020).
6. **Abandoned dependency** reporting via EOL and last-release data (ASC-ARC-02 extends to unmaintained packages in Phase 11).

## Alternatives considered

Pre-approved package allowlist (unworkable at npm scale) · no policy (status quo risk) · commercial curation service (possible later; cost).

## Decision drivers

Block the worst (malicious) hard. Inform the rest. Keep developer flow.

## Consequences

Licence "review" items need a Legal contact and SLA.

## Security implications

The cooldown trades a few days of feature latency for materially reduced exposure to hijacked releases.

## Operational implications

Licence policy owner (OSS governance / Legal). Quarterly review of exceptions.
