# ADR-003: OWASP ASVS as the application security requirement layer

**Status:** Accepted (2026-10-20), implemented  ·  **Related:** [SAMM/ASVS methodology Part B](../docs/standards/samm-asvs-mapping.md#part-b-owasp-asvs-operational-not-a-checklist)

## Context

SAMM measures *practices*. Teams also need concrete, testable *technical requirements* for the software itself, scaled to risk.

## Decision

Adopt **OWASP ASVS 5.0** as the technical requirement baseline:

- Import requirements from the official release artefacts (machine-readable), pinned. Never hand-transcribe.
- **Tier → level** (PROPOSED): Tier 1 → L3, Tier 2 → L2, Tier 3 → L1 + automatable L2, Tier 4 → L1.
- **Applicability by capability profile** (`.security/asvs.yaml`), so teams see only the requirements relevant to their app.
- **Requirement status is derived from evidence** (tests tagged with ASVS IDs, configuration checks, manual review records). Scanner silence is `SCANNED_NO_ISSUES`, never `VERIFIED`.
- **MASVS** for mobile applications: PROPOSED extension when the first mobile app is onboarded.

## Alternatives considered

| Option | Assessment |
|---|---|
| ASVS 4.0.3 | More third-party CWE↔ASVS mappings exist today. But 5.0 is current, restructured, and where the community is moving. Migrating later costs more than building mappings now. |
| Custom internal requirement set | Unrecognised, costly to maintain, duplicates ASVS. |
| NIST SP 800-53 / ISO 27001 Annex A | Organisational and system controls, not application-level verification requirements. Mapped via CSF where needed. |
| OWASP Top 10 as requirements | Awareness document, not a requirement standard. Used for training and reporting categories only. |

## Decision drivers

Testable requirements · risk-scaled levels · open standard · maps to CWE and SAMM (Security Requirements, Requirements-driven Testing).

## Consequences

- CWE → ASVS 5.0 mappings for SAST/DAST rules must be built and maintained (backlog E12-F03).
- Teams adopt a test-tagging convention (JUnit properties) to turn tests into requirement evidence.
- L3 for Tier 1 is demanding. Expect exceptions early. Target dates are phased.

## Security implications

Requirement status must not overstate assurance. The "scanner silence ≠ verified" rule exists specifically to prevent false confidence.

## Operational implications

AppSec maintains the applicability mapping and the CWE↔ASVS mapping. Re-import on ASVS patch releases.
