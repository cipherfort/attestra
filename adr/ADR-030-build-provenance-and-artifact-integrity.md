# ADR-030: Build provenance and artifact integrity

**Status:** Accepted (2026-10-20), implemented, amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** ADR-006, ADR-016, ADR-028, controls ASC-BLD-06, ASC-DEP-03

## Context

Proving "what runs in production was built from reviewed source by the controlled pipeline" requires provenance at build and verification at deploy. GitHub artifact attestations (Sigstore-backed, SLSA provenance format) are native to GitHub Actions. For private/internal repositories they require GitHub Enterprise Cloud (assumption A-05).

## Decision

1. **Generate** SLSA build provenance for release artifacts (container images, packages) with `actions/attest-build-provenance` inside the build job, via `security-workflows/provenance.yml`. Target: **SLSA Build L2** for all Tier 1/2 artifacts. **L3** where builds run in the reusable workflow on ephemeral runners (isolated, non-falsifiable provenance).
2. **Verify** before deploy: `gh attestation verify <artifact> --owner <org> --signer-workflow <approved workflow>` in CD (`deploy-evidence.yml`). Container Apps has no admission control, so verification lives in CD. For Kubernetes targets, admission policy (Ratify / Kyverno / Azure Policy for AKS) is PROPOSED.
3. **Record** verification outcomes as `deploy.record` evidence binding digest → environment (ASC-DEP-03), feeding "what is deployed" for CVE impact and freshness.
4. **The platform's own images** follow the same path, and the platform CD refuses unattested images.
5. The evidence manifests themselves are attested (ADR-016). The same mechanism covers both artifacts and evidence.

## Alternatives considered

| Option | Why not |
|---|---|
| Cosign keyless signing with a public Rekor log | For private repos it would publish signing metadata (repo identity, timing) to a public log. GitHub's private-repo attestation path avoids that. |
| Notation (Notary v2) with Key Vault keys | Viable for Azure-centric registries. Key management overhead. Keep as an option if attestations are unavailable on the org plan. |
| No provenance; rely on registry access control | Doesn't prove build origin. Fails SLSA and SSDF PS.2/PS.3. |

## Decision drivers

Native to GitHub · keyless (no signing keys to manage) · verifiable at deploy.

## Consequences

Requires verifying A-05 (Phase 0). The fallback is Notation with Key Vault-held keys.

## Security implications

Prevents artifact substitution between build and deploy, and binds deployed digests to evidence.

## Operational implications

CD changes in app repos (provided by `deploy-evidence.yml`). Teams with non-GitHub CD need an equivalent verification step (documented).
