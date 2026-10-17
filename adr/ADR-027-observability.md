# ADR-027: Observability

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-020, ADR-024

## Context

A platform that reports on others' controls must make its own health visible, especially **connector health**. A silently failing connector produces stale data that looks like "fine".

## Decision

- **OpenTelemetry** SDK in all three apps → **Azure Monitor (Application Insights)** for traces, metrics and logs. W3C trace context propagated from webhook → job → evaluation.
- **Structured JSON logs** with `request_id`, `job_id`, `app_key`. A redaction filter for tokens, secrets and finding descriptions. **Audit events are a separate ledger** (DB + Sentinel), not just logs.
- **SLOs** (initial):

| SLO | Target |
|---|---|
| UI/API availability (business hours) | 99.5% |
| Evidence ingestion latency (run completed → evidence stored) | p95 < 10 min |
| Control re-evaluation lag after evidence | p95 < 5 min |
| Connector freshness (time since last successful sync) | < 2 × schedule interval |
| Queue age per queue | p95 < 5 min (`ingest`, `evaluate`) |
| Dead-lettered jobs | 0 unacknowledged > 24h |
| Daily integrity verification | 100% of days succeed |

- **Connector health is shown in the product UI.** Every view that depends on a connector shows "data as of …" and a stale banner. A connector outage turns affected control evaluations to `error` (last known state shown), never silently `satisfied`.
- **Alerting:** Azure Monitor alerts → on-call (Teams + paging for P1). Runbooks are linked from every alert.

## Alternatives considered

Self-hosted Prometheus/Grafana/Loki (more control, more ops) · vendor APM (cost, data egress).

## Decision drivers

Honest data-freshness signalling · managed services · standards (OTel) for portability.

## Consequences

Some instrumentation effort in every connector (metrics: calls, errors, rate-limit remaining, last success).

## Security implications

Telemetry must not leak sensitive data. Redaction is tested. App Insights and the Logs Ingestion endpoint move behind private link (AMPLS): PROPOSED, not yet in `examples/terraform/azure`.

## Operational implications

On-call rota for the platform team (business hours + best effort out of hours, PROPOSED).
