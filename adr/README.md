# Architecture Decision Records

Format for every ADR: Status · Context · Decision · Alternatives · Decision drivers · Consequences · Security implications · Operational implications.
ADR-001 to ADR-031 were **Proposed** during the original design; ADR-032 is **Accepted**. Decisions that change an invariant need a new ADR (see GOVERNANCE.md). ADRs marked ★ are the decisions most worth challenging, because they shape everything else.

| ADR | Title | Key decision in one line |
|---|---|---|
| [001](ADR-001-platform-purpose-and-scope.md) ★ | Platform purpose and scope | Build an assurance layer over existing tools. Re-check the ASPM market at Phase 0 exit. |
| [002](ADR-002-owasp-samm-maturity-framework.md) | OWASP SAMM as maturity framework | SAMM 2.0 imported verbatim. Maturity derived from evidence, with provenance shown. |
| [003](ADR-003-owasp-asvs-requirements.md) | OWASP ASVS as requirements | ASVS 5.0, tier → level, capability-scoped. Scanner silence ≠ verified. |
| [004](ADR-004-evidence-driven-security-model.md) ★ | Evidence-driven model | Confidence levels C0–C3/M1–M2. C0 never satisfies a control. Activity controls need ≥ C2. |
| [005](ADR-005-github-primary-source-integration.md) ★ | GitHub as primary source | Read-only GitHub App. **Pull-based** evidence. No platform credentials in repos. |
| [006](ADR-006-github-actions-security-pipeline.md) | GitHub Actions security pipeline | Separate `security-workflows` repo, one caller per repo, SHA-pinned, adapters per capability |
| [007](ADR-007-evidence-storage-architecture.md) | Evidence storage | Azure Blob WORM, content-addressed, private. Metadata in PostgreSQL. |
| [008](ADR-008-postgresql-data-model.md) | PostgreSQL data model | PG16 Flexible, separate server, ledgers + projections, RLS |
| [009](ADR-009-sbom-standard.md) | SBOM | Source + build SBOMs bound to digest. Quality gate. Honest "possibly affected". |
| [010](ADR-010-cyclonedx-vs-spdx.md) | CycloneDX vs SPDX | CycloneDX canonical. SPDX accepted and converted. |
| [011](ADR-011-vulnerability-risk-model.md) ★ | Vulnerability risk model | Likelihood × impact with context, versioned and explainable. SSVC evaluated later. |
| [012](ADR-012-cvss-epss-usage.md) | CVSS / EPSS / KEV usage | Each signal for what it measures. Never CVSS alone. |
| [013](ADR-013-rbac-model.md) | RBAC model | Scoped roles, SoD in code, 404 on out-of-scope, admins lack default detail access |
| [014](ADR-014-authentication-architecture.md) | Authentication | Entra OIDC via BFF. Federation everywhere. No API keys. |
| [015](ADR-015-secrets-management.md) | Secrets management | Key Vault private, no secrets in Terraform state, rotation schedule |
| [016](ADR-016-evidence-immutability.md) ★ | Evidence immutability | WORM + insert-only ledgers + hash chain + external checkpoint in Sentinel |
| [017](ADR-017-evidence-retention.md) | Retention | 24 months online, 7 years archive (proposed, needs records-management approval) |
| [018](ADR-018-jira-integration.md) ★ | Jira integration | Platform is the only ticket writer. Grouped dedup keys. **Closure only by re-scan evidence.** |
| [019](ADR-019-cloud-integration.md) | Cloud integration | Resource Graph/Defender + Security Hub aggregator. Tag-based attribution. |
| [020](ADR-020-siem-integration.md) | SIEM integration | 11 curated event types to Sentinel, not every finding |
| [021](ADR-021-security-exceptions.md) ★ | Security exceptions | Platform-only, SoD, expiry → finding, tool suppressions not trusted |
| [022](ADR-022-multi-directorate-model.md) | Multi-directorate model | Single deployment, org-unit RLS, org-wide config |
| [023](ADR-023-api-architecture.md) | API architecture and stack | REST + OpenAPI 3.1, FastAPI/Python, React/TS SPA |
| [024](ADR-024-event-queue-architecture.md) | Event/queue | PostgreSQL queue + transactional outbox. Service Bus as upgrade path. |
| [025](ADR-025-deployment-model.md) | Deployment model | Container Apps in a private VNet. Only the webhook receiver is public. |
| [026](ADR-026-disaster-recovery.md) | Disaster recovery | RTO 4h / RPO 15 min. Geo-backup. 6-monthly restore drills. |
| [027](ADR-027-observability.md) | Observability | OTel → Azure Monitor. Connector freshness visible in the product. |
| [028](ADR-028-supply-chain-security.md) | Supply-chain security | Actions allowlist + SHA pins. Public source ≠ public evidence. |
| [029](ADR-029-open-source-dependency-governance.md) | OSS dependency governance | Licence policy, malicious = hard block, 3-day cooldown |
| [030](ADR-030-build-provenance-and-artifact-integrity.md) | Build provenance | GitHub attestations (SLSA L2→L3), verified in CD |
| [031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) ★ | Integrations owned by the project | Fresh project: every external system is created as code and bootstrapped by this project. Nothing assumes another team. |
| [032](ADR-032-open-source-product.md) ★ | Open-source product | Apache-2.0, vendor-neutral core + plugins, GitHub + GitLab at 1.0, Compose + Helm, OWASP after 1.0 |
| [033](ADR-033-gitlab-evidence-trust.md) ★ | GitLab evidence trust | Merged job must equal the approved component at its pinned SHA; GitLab evidence capped at C2 |

Relationship to the earlier prototype scaffold: **reference only** ([ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md)). The platform deploys its own Dependency-Track and DefectDojo (`examples/terraform/azure/modules/scanners`). The earlier amendments (no repo-held DD/DT keys, workflows in `security-workflows` pinned by SHA, the platform as the only Jira writer) remain the design.
