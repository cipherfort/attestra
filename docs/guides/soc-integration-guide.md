# SOC Integration Guide

| | |
|---|---|
| Audience | SOC analysts and engineers, platform team |
| Status | IMPLEMENTED (export, dedup, dispatch; `modules/sentinel` creates the table, DCR and rules). Event catalogue REQUIRES HUMAN APPROVAL (SOC lead). |
| Decision | [ADR-020](../../adr/ADR-020-siem-integration.md) · event catalogue [`config/siem-events.yaml`](../../config/siem-events.yaml) |

## 1. What the SOC receives (and doesn't)

Eleven curated event types that indicate **active risk or possible compromise**: exposed active secrets, malicious packages, KEV-listed vulnerabilities on internet-facing apps, P1 SLA breaches, evidence integrity failures, forged-evidence attempts, SoD violation attempts, bulk exports, privileged activations, mass-closure anomalies, and daily integrity checkpoints. **Routine findings are not sent.**

## 2. Sentinel setup

| Step | Owner | Detail |
|---|---|---|
| 1 | SOC | Create custom table `AppSecPlatform_CL` (schema below) and a Data Collection Rule + endpoint |
| 2 | SOC/IAM | Grant the platform worker's managed identity **Monitoring Metrics Publisher** on the DCR |
| 3 | Platform | Configure DCE URL, DCR immutable ID and stream name in platform config |
| 4 | SOC | Deploy analytics rules (the Azure example's `examples/terraform/azure/modules/sentinel`) and set table retention ≥ evidence retention (for `checkpoint.daily`) |

**Table schema**

| Column | Type | Notes |
|---|---|---|
| TimeGenerated | datetime | `occurred_at` |
| EventId | string | Idempotency key |
| EventType | string | e.g. `secret.exposed_active` |
| Severity | string | informational / low / medium / high |
| AppKey, AppTier | string, int | Correlation with app inventory |
| Repo | string | `org/repo` |
| ResourceIds | dynamic | Azure resource IDs / AWS ARNs |
| VulnIds | dynamic | CVE/GHSA/MAL ids |
| Actor | string | Entra object ID or GitHub login |
| PlatformUrl | string | Deep link (requires platform access) |
| CorrelationId | string | |
| Details | dynamic | Minimal, no secret values |

## 3. Example analytics rules (KQL sketches)

**Exposed secret used after exposure** (correlate with Entra service principal sign-ins):
```kusto
AppSecPlatform_CL
| where EventType == "secret.exposed_active"
| extend AppId = tostring(Details.client_id)
| join kind=inner (AADServicePrincipalSignInLogs | where TimeGenerated > ago(1d)) on $left.AppId == $right.AppId
| where TimeGenerated1 > TimeGenerated
```

**KEV vulnerability on internet-facing app + WAF hits on the app's host:**
```kusto
AppSecPlatform_CL
| where EventType == "vuln.kev_internet_exposed"
| extend Host = tostring(Details.host)
| join kind=inner (AzureDiagnostics | where Category == "FrontDoorWebApplicationFirewallLog") on $left.Host == $right.host_s
```

**Repeated forged evidence attempts by one actor:**
```kusto
AppSecPlatform_CL
| where EventType == "evidence.untrusted_producer"
| summarize count() by Actor, bin(TimeGenerated, 1d) | where count_ >= 3
```

The rules are illustrative. Table and field names for source logs must be confirmed against the workspace.

## 4. Exabeam (if used)

PROPOSED: forward the same JSON events via Exabeam's HTTP/syslog collector. Field mapping to be agreed with the SOC.

## 5. Escalation and response

| Event | SOC response | AppSec contact |
|---|---|---|
| `secret.exposed_active` | Hunt for credential use. Confirm rotation with the owner. | Platform on-call / AppSec |
| `package.malicious_detected` | Incident: assess CI runners and secrets exposed to builds | AppSec lead |
| `evidence.integrity_failure` | Incident: possible platform compromise | Platform on-call + Head of AppSec |
| Others | Triage per SOC playbook | AppSec triage channel |
