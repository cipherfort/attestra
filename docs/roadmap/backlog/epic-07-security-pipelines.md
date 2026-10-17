# E07: Security Pipelines (`security-workflows`)

**Goal:** A paved-road, tool-replaceable security pipeline that produces verifiable evidence. Design: [pipeline architecture](../../architecture/05-pipeline-architecture.md).

## F01: Foundations

### E07-F01-S01: Create `security-workflows` repo with hardened governance · M · Phase 1
- **Story:** As the platform team, I want a dedicated workflows repo with strict controls, so that the code that runs in every pipeline is protected.
- **AC:** Ruleset: 2 approvals, CODEOWNERS = platform team, signed commits, no force-push. Its own CI: actionlint, zizmor, canary e2e. `permissions: {}` default. Actions allowlist applies.
- **Security:** Write access is effectively write access to every consumer pipeline. Membership is reviewed quarterly.

### E07-F01-S02: `emit-evidence` composite action · M · Phase 1
- **Story:** As every capability workflow, I need a shared step that writes the manifest, attests it and uploads the artifact, so that evidence is uniform and verifiable.
- **Technical:** Builds `evidence-manifest.json` (schema-validated in the action), computes SHA-256 of outputs, `actions/attest` with predicate type `https://cipherfort.github.io/attestra/attestation/evidence/v1`, uploads artifact `aap-evidence-<capability>` (retention 3 days, 1 day if public).
- **AC:** The manifest validates against `schemas/evidence/evidence-manifest.schema.json`. The attestation verifies with `gh attestation verify --signer-workflow`. Public-repo mode prints counts only.
- **Tests:** Canary run. A schema-invalid manifest fails the step.

### E07-F01-S03: `suite.yml` with detection · M · Phase 3
- **Story:** As a team, I want one caller that auto-detects languages, ecosystems, IaC, Dockerfiles, OpenAPI and workflows, and runs the right capabilities, so that onboarding is one file.
- **AC:** Detection output shown in the job summary. Override inputs work. Unsupported languages are listed (not silently skipped). PR p90 added time ≤ 10 min (PS-11).

## F02: Capability adapters

### E07-F02-S01: SAST adapter (CodeQL) · M · Phase 1 (thin slice) → 3
- **AC:** Runs CodeQL for detected languages with a tier-appropriate suite. SARIF → GHAS. Manifest includes languages detected vs analysed. Accepts org default setup as an alternative (platform reads the analyses API).

### E07-F02-S02: SCA + malicious package adapter (OSV-Scanner) and dependency review · M · Phase 3
- **AC:** Scans all lockfiles. `MAL-*` advisories reported distinctly. Dependency review on PRs with org config (fail on new critical/high when the gate is enabled, licence deny list). Evidence for both.

### E07-F02-S03: IaC adapter (Checkov + Trivy config) and container adapter (Trivy) · M · Phase 3
- **Technical:** Port the image-scan logic from the earlier prototype (keep the SHA-pinned Trivy). Remove the DefectDojo push. Digest-bound container evidence.
- **AC:** SARIF to GHAS (categories per tool). Manifests bound to commit or image digest.

### E07-F02-S04: SBOM adapter (cdxgen / Syft / Terraform lock parser) · M · Phase 3
- **Technical:** Port the Terraform lock-file → CycloneDX parser from the infra repo's `sbom-scan.yml` (already debugged in the pilot). cdxgen for source. Syft for images. **No direct upload to Dependency-Track** (the platform forwards).
- **AC:** Pilot repo C produces an SBOM with ≥ 95% purl coverage. The Terraform parser handles non-registry hosts.

### E07-F02-S05: Workflow-lint, DAST/API, provenance, deploy-evidence, test-evidence adapters · S · Phase 3–8
- **AC per adapter:** manifest + attestation. DAST records target, auth mode and URLs crawled (inconclusive below threshold). Provenance via `attest-build-provenance`. `deploy-evidence` runs `gh attestation verify` on the deployed digest. `test-evidence` extracts JUnit testcases with `asvs`/`threat` properties.

## F03: Release and migration

### E07-F03-S01: Release process and trusted-producer registration · M · Phase 3
- **AC:** Tag → release notes → PR to `config/trusted-producers.yaml` adding the release SHA. 90-day retirement for old SHAs. Dependabot config template for consumers.

### E07-F03-S02: Migrate pilot repos off infra-repo workflows; remove DD/DT keys · M · Phase 3–9
- **AC:** Pilot repos use `aap-security.yml`. Repo secrets `DEFECTDOJO_API_KEY` / `DEPENDENCY_TRACK_API_KEY` deleted **and the keys rotated** (PS-14). No double import into DD during the overlap.
