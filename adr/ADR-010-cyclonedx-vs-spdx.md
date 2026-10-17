# ADR-010: CycloneDX as canonical SBOM format; SPDX accepted

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-009

## Context

Two mature SBOM standards exist: **CycloneDX** (OWASP / Ecma TC54, security-oriented: vulnerabilities, VEX, services, dependencies) and **SPDX** (Linux Foundation, ISO/IEC 5962, licence-compliance heritage). Dependency-Track ingests **CycloneDX only**. GitHub's native dependency-graph export is **SPDX**. Customers or regulators may request either.

## Decision

- **Canonical internal format: CycloneDX JSON (≥ 1.5).** All platform-generated SBOMs use it.
- **Accept SPDX 2.3 JSON** as input. Convert to CycloneDX on ingestion with a maintained converter selected in E10 (candidates: CycloneDX CLI, protobom-based tooling). Converted SBOMs carry `confidence_reasons: ["converted_from_spdx"]` and quality checks apply after conversion.
- **Export in either format** on request (Syft can emit SPDX from the same image; source SBOMs are converted).
- Store the **original** submitted document in WORM storage regardless of conversion.

## Alternatives considered

| Option | Why not |
|---|---|
| SPDX canonical | DT incompatibility would force conversion on every ingest into the CVE engine. Weaker native vulnerability/VEX modelling for our use. |
| Support both natively end-to-end | Two parsers and two quality models with no benefit to the core use cases. |

## Decision drivers

Dependency-Track compatibility · VEX support · security use case first.

## Consequences

Conversion loses some SPDX-specific licence detail. Licence evaluation uses the original SPDX where present.

## Security implications

Converters parse untrusted input and run in the sandboxed ingestion worker with size limits (threat T-05).

## Operational implications

Track both specs' releases. Re-validate converters on version bumps.
