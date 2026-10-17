# Application Security Incident Runbook: TEMPLATE

> Copy into your repository (e.g. `docs/runbooks/security-incident.md`) and fill in. Required for Tier 1 (ASC-OPS-02, reviewed or exercised every 12 months; record the exercise in the platform). Keep it short and current. It is used under pressure.

| | |
|---|---|
| Application | APP-nnnnn · name · tier |
| Last reviewed / exercised | YYYY-MM-DD (link to the platform evidence record) |

## 1. Contacts

| Role | Name | How to reach (in and out of hours) |
|---|---|---|
| Technical owner | | |
| Deputy | | |
| Business owner | | |
| Security champion | | |
| SOC | | 24×7 number / channel |
| Hosting / cloud platform | | |
| Key suppliers | | |

## 2. Know your system

Links: architecture / threat model (`.security/threat-model/`), dashboards, log queries (Sentinel workspace + saved KQL for this app's `app_key`), deployment pipeline, environments.

## 3. Kill switches and containment options

| Option | How | Impact |
|---|---|---|
| Block traffic at the edge (WAF rule / Front Door) | | |
| Disable a feature (flag) | | |
| Revoke all user sessions/tokens | | |
| Scale to zero / maintenance mode | | |
| Disable an integration (e.g. third-party API key) | | |

## 4. Credential rotation

| Credential | Where stored | How to rotate | Who can |
|---|---|---|---|
| | Key Vault | | |

## 5. Data breach decision points

What personal or sensitive data could be exposed (from `application.yaml` data stores) · when to involve the DPO (immediately on suspected personal-data exposure) · regulatory notification timelines (e.g. 72h where UK GDPR applies; the DPO decides) · who decides on user communication.

## 6. Recovery

Restore procedure (backups, PITR) · how to redeploy a known-good, attested version · verification steps before reopening.

## 7. After the incident

Post-incident review · threat-model update · new tests for the abuse path · findings recorded in the platform.
