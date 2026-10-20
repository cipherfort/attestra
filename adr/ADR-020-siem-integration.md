# ADR-020: SIEM / SOC integration

**Status:** Accepted (2026-10-20), implemented; the Azure services named here are one deployment option since [ADR-032](ADR-032-open-source-product.md) made the product provider-neutral, amended by [ADR-031](ADR-031-integrations-owned-and-bootstrapped-by-the-project.md) (2026-10-08)  ·  **Related:** [`config/risk-model.yaml`](../config/risk-model.yaml) `soc_escalation`, [Governance section 5](../adoption-kit/governance/governance-model.md#5-escalation)

## Context

Sending every scanner finding to the SOC creates noise the SOC cannot act on. Some application-security events, however, indicate active risk or possible compromise and need SOC visibility and correlation.

## Decision

Emit a **curated set of events** as structured JSON to **Microsoft Sentinel** via the Azure Monitor **Logs Ingestion API** (DCR + custom table `AppSecPlatform_CL`), authenticated with managed identity. Other SIEMs (Splunk, Elastic, Exabeam, …) receive the same events through the HTTPS sink (JSON or Splunk HEC) or the syslog sink (RFC 5424 over TLS); one SIEM sink is active per deployment.

| Event type | Severity | Why the SOC needs it | Suggested SOC action |
|---|---|---|---|
| `secret.exposed_active`: verified-valid secret exposed | High | Credential may be abused now. Correlate with sign-in/cloud logs. | Hunt for use of the credential. Confirm rotation. |
| `package.malicious_detected` in a dependency set or build | High | Code execution in CI or runtime | Treat CI runners and secrets as compromised until shown otherwise |
| `vuln.kev_internet_exposed`: KEV-listed vuln on an internet-facing app | High | Active exploitation campaigns | Correlate with WAF/app logs for exploitation attempts |
| `finding.p1_sla_breached` | Medium | Known exploitable risk left open | Monitoring uplift on the affected app |
| `evidence.integrity_failure` (hash chain / blob mismatch) | High | Possible tampering with assurance records | Investigate platform compromise |
| `evidence.untrusted_producer` (repeated forged-evidence attempts) | Medium | Possible insider attempt to falsify assurance | Investigate the actor |
| `authz.sod_violation_attempt` | Medium | Attempted self-approval | Review the actor |
| `data.bulk_export` | Low/Medium | Possible exfiltration of the vulnerability map | Baseline and alert on anomalies |
| `platform.privileged_activation` (PIM) | Low | Audit | Correlate with changes |
| `finding.mass_closure_anomaly` (> N closures/hour from a source) | Medium | Upstream tool compromise or abuse (threat T-13) | Investigate the source system |
| `checkpoint.daily` | Info | External anchor for tamper evidence (ADR-016) | Retain only |

**Schema:** `{event_type, severity, occurred_at, app_key, app_tier, repo, resource_ids[], vuln_ids[], actor (entra oid / github login), platform_url, correlation_id}`. Correlation keys are `app_key`, cloud resource IDs and GitHub actor, so Sentinel can join with Azure/AWS activity and GitHub audit logs.

**Incident triggers** are Sentinel analytics rules shipped as code (KQL in `infrastructure/sentinel/`, Stage 9). Thresholds are owned by the SOC.

**Not sent:** routine findings, control state changes, evaluations. Those stay in the platform.

## Alternatives considered

Send all findings (noise, cost, SOC rejection) · send nothing (loses correlation for active-risk events) · SOC polls the platform API (inverts responsibility, slower).

## Decision drivers

Actionability for the SOC · correlation with other telemetry · cost.

## Consequences

The event catalogue is versioned and changes go through the SOC lead. Delivery is at-least-once (outbox) with an idempotency key (`event_id`).

## Security implications

Events contain minimal detail (identifiers and links, not exploit details). Sentinel retention for `checkpoint.daily` must cover evidence retention.

## Operational implications

**Created by the project** (`examples/terraform/azure/modules/sentinel`, ADR-031): DCR/DCE, custom table whose columns are generated from the code (tested), `Monitoring Metrics Publisher` on that DCR only, analytics rules including a missing-checkpoint rule. The event list still REQUIRES HUMAN APPROVAL (SOC lead).
