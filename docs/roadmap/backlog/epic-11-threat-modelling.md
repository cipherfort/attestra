# E11: Threat Modelling

**Goal:** Version-controlled, structured threat models that link threats to mitigations, tests and accepted risks.

## F01: Threat-model contract

### E11-F01-S01: Threat-model schemas and kit · M · Phase 4
- **Story:** As a champion, I want a template and schemas for `.security/threat-model/` (system context, DFD with trust boundaries, assets, threats with STRIDE, mitigations, residual risk), so that models are consistent and machine-checkable.
- **Technical:** JSON Schemas for `assets.yaml`, `threats.yaml`, `mitigations.yaml`, `residual-risk.yaml`. Markdown templates with Mermaid DFD conventions (trust boundaries as subgraphs). Threat IDs `TM-nn` stable across versions.
- **AC:** A worked example for a pilot app passes the schema. The kit is documented in the Threat Modelling Standard (Stage 3). Attack trees supported as an optional `attack-trees/` directory (Mermaid).
- **Tests:** Schema fixtures.
- **Progress:** schema + full worked example IMPLEMENTED (`schemas/repo-contract/threat-model.schema.json`, `templates/repo-contract/.security/threat-model/`), validated with reference-integrity checks.

## F02: Parsing and linkage

### E11-F02-S01: Parse threat models per commit · M · Phase 4
- **AC:** On a push touching `.security/threat-model/**`, parse → `threat_models`, `threats`, `mitigations` (unique per repo + commit) and `repo.threat_model` C1 evidence. Validation errors shown.

### E11-F02-S02: Mitigation reference resolution · M · Phase 4
- **AC:** References to `ASC-*`, ASVS IDs, Jira keys, test IDs and exception IDs are resolved, and `resolved=false` is flagged. ASC-TM-03 evaluates high threats lacking resolved mitigations or approved residual-risk exceptions.

## F03: Review

### E11-F03-S01: Threat-model review workflow · M · Phase 6
- **AC:** Review bound to the commit SHA of the files reviewed. M2 for Tier 1/2 (independent reviewer). Architecture-change signals (PR label, DFD change, exposure change) invalidate it (event_bound freshness).
