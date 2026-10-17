# E20: Operations

**Goal:** The platform is deployable, observable, recoverable and supportable.

**Progress (Stage 9):** `aap integrations status|run`, `connector_runs`, Integrations page, local integration stack and the integration bootstrap runbook IMPLEMENTED.

## F01: Infrastructure

### E20-F01-S01: Terraform for platform environments · M · Phase 1
- **AC:** Modules: network (VNet integration, private DNS, NAT/firewall rules), Container Apps env (workload profiles, internal), PG Flexible (zone-redundant HA, **geo-redundant backup on creation**, Entra auth), Storage (WORM containers, private endpoint, shared key disabled), Key Vault, ACR Premium, Log Analytics/App Insights. `dev` and `prod` envs. Checkov clean or with recorded exceptions. azurerm `~> 4.x`.
- **Depends on:** The platform's own VNet (`modules/platform`, IMPLEMENTED as code).

### E20-F01-S02: Platform CI/CD with provenance verification · M · Phase 1
- **AC:** PR: lint, type-check, unit, SAST, SCA, secrets, IaC, container scan, SBOM, dependency review, coverage. Main: build → attest → deploy to dev (migration as a Container Apps job) → smoke → manual approval → prod. CD verifies the image attestation before deploy (ADR-030). Post-deploy verification (health, synthetic webhook).

## F02: Observability

### E20-F02-S01: OpenTelemetry, SLOs and alerts · M · Phase 4
- **AC:** Traces webhook → job → evaluation. SLO dashboards (ADR-027). Alerts with linked runbooks. A redaction test on logs.

### E20-F02-S02: Connector health in product · M · Phase 4–8
- **AC:** Per connector: last success, error rate, rate-limit headroom. A stale connector turns dependent evaluations to `error` with the last known state and shows a banner.

## F03: Resilience

### E20-F03-S01: Backup, restore and DR drill · M · Phase 9
- **AC:** PITR restore to a scratch server + chain verification succeeds within RTO. Regional restore tabletop. The drill record is stored as platform evidence.

### E20-F03-S02: Runbooks · M · Phase 9
- **AC:** Runbooks: platform incident, CVE emergency (including the DT fallback query), evidence integrity mismatch, key rotation, connector outage, dead-letter replay, partition maintenance, onboarding support.
