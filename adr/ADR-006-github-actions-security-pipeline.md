# ADR-006: GitHub Actions security pipeline (central reusable workflows)

**Status:** Accepted (2026-10-20), implemented; the Azure services named here are one deployment option since [ADR-032](ADR-032-open-source-product.md) made the product provider-neutral, amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Amends (historical reference):** the earlier prototype's ADR-0001 (workflow location, pinning, DD/DT push)  ·  **Related:** [Pipeline architecture](../docs/architecture/05-pipeline-architecture.md)

## Context

Hundreds of repos need consistent security testing that produces verifiable evidence. The pilot's reusable workflows are referenced `@main` (CS-7) and push to DD/DT with repo-held keys (CS-1).

## Decision

1. A dedicated **`security-workflows`** repository holds a `suite.yml` reusable workflow plus one reusable workflow per capability, and an `emit-evidence` composite action.
2. App repos have **one caller** (`aap-security.yml`), **pinned by commit SHA**, updated by Dependabot.
3. **Capability adapters** wrap tools. The platform reasons about capabilities and evidence types, not tool names. Default tools: CodeQL, OSV-Scanner, dependency-review, Checkov + Trivy config, Trivy image, cdxgen/Syft, zizmor + actionlint, ZAP, Schemathesis, `attest-build-provenance`.
4. Every adapter emits SARIF (to GHAS) where applicable, and an **attested evidence manifest**.
5. Releases are tagged. Release SHAs are registered as **trusted producers**. Retired SHAs are trusted for 90 days.
6. Gates are **GitHub-native** (rulesets, required checks, code-scanning merge protection). The platform is never in the merge path.
7. An org ruleset **requires the `aap-security` workflow** for in-scope repos (organization rulesets need GitHub Team/Enterprise, decision D-018; created by `examples/terraform/azure/envs/github` with `org_rulesets_available`, ADR-031).

## Alternatives considered

| Option | Why not |
|---|---|
| Copy workflow files into each repo | Drift. Pinning chaos. Evidence producer identity unverifiable. |
| Nine separate caller files (brief's sketch) | Nine pins to maintain per repo, and more drift. One suite with auto-detection is simpler for teams. |
| CodeQL default setup only | Covers SAST only. Kept as an acceptable SAST evidence source (read via API). |
| External CI (Jenkins/Azure DevOps) for security scans | Splits the developer experience. Loses native GHAS integration. |
| Commercial pipeline-security SaaS | Cost per repo. Data egress. Lock-in. The adapter model keeps this option open per capability. |

## Decision drivers

Consistency · verifiable producer identity · vendor neutrality · developer experience · platform not in the critical path.

## Consequences

- Write access to `security-workflows` is effectively write access to every pipeline. It gets stricter CODEOWNERS (2 approvals), signed commits, and its own CI with canary repos.
- Teams lose the ability to customise scanners freely. Overrides are inputs, not forks.

## Security implications

Third-party actions pinned by SHA and restricted by an org allowlist (ADR-028), minimal `permissions:` per job, no `pull_request_target`, and suppressed detail on public repos. Together these address threats T-14, T-15 and T-16.

## Operational implications

A release process with canaries. Deprecation notices. A support channel for teams. Runner capacity planning for weekly scheduled scans (staggered).
