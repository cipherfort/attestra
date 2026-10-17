# E18: SOC Integration

**Goal:** Curated, actionable AppSec events in the organization's SIEM (Sentinel, or another over HTTPS or syslog). Design: [ADR-020](../../../adr/ADR-020-siem-integration.md).

**Progress (Stage 9):** curated event derivation (8 types), per-window dedup, daily chain checkpoint, at-least-once dispatch to the Logs Ingestion API, Terraform table/DCR/rules IMPLEMENTED. Event list still REQUIRES HUMAN APPROVAL (SOC lead).

## F01: Event export

### E18-F01-S01: Event catalogue sign-off · M · Phase 8
- **AC:** The SOC lead approves the 11 event types, severities, schema and suggested actions. The catalogue is versioned in `config/siem-events.yaml`.

### E18-F01-S02: Sentinel Logs Ingestion API exporter · M · Phase 8
- **AC:** Outbox → exporter → DCR/custom table `AppSecPlatform_CL` with managed identity. At-least-once with `event_id` idempotency. Daily checkpoints included (ADR-016). Delivery health metric.
- **Depends on:** DCR/DCE + role assignment (`modules/sentinel`, IMPLEMENTED as code).

## F02: Detection content

### E18-F02-S01: Sentinel analytics rules as code · S · Phase 8–9
- **AC:** KQL rules for: active secret + sign-in correlation, KEV-internet + WAF hits, evidence integrity failure, SoD attempts, bulk export anomaly, mass closure anomaly. Deployed by IaC (`infrastructure/sentinel/`). Each rule tested with synthetic events.
