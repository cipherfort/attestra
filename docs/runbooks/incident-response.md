# Incident Response Runbook: FortProof

| | |
|---|---|
| Scope | Security incidents **affecting the platform itself** (compromise, data exposure, evidence tampering, credential leak). For incidents in *applications*, teams follow the organisation's IR process and their app runbook ([template](application-incident-runbook-template.md)). |
| Status | DESIGNED. Aligns with the organisation's IR policy; the SOC leads major incidents. |
| Contacts | Platform on-call · platform tech lead · AppSec lead · SOC (24×7) · DPO (personal data) |

## 1. Severity

| Sev | Examples | Response |
|---|---|---|
| **P1** | GitHub App private key exposed · evidence integrity failure (chain mismatch) · confirmed unauthorised access to finding data · compromise of `security-workflows` | Immediate. SOC engaged. AppSec lead informed. |
| **P2** | Repeated forged-evidence attempts · SoD-bypass attempt · webhook secret exposure · suspicious bulk export | Within 1 business hour |
| **P3** | Single rejected forged-evidence attempt · misconfiguration without exposure | Next business day |

## 2. Phases

### Detect
Sentinel analytics on platform events (`evidence.integrity_failure`, `evidence.untrusted_producer`, `authz.sod_violation_attempt`, `data.bulk_export`, `platform.privileged_activation`) · Key Vault access anomalies · GitHub audit log (App token from unexpected IP) · Defender alerts · user reports.

### Contain (by scenario)

| Scenario | Containment steps |
|---|---|
| **GitHub App key compromise** | Generate a new key, revoke the old key in the App settings (immediate invalidation), update Key Vault, restart workers. Review GitHub audit log for App token usage since exposure. The App is read-only: assess *read* exposure (code, alerts). |
| **Evidence tampering suspected** | Freeze: set `INGESTION_PAUSED=true` and disable the evaluator sweep. Snapshot the DB (PITR marker). Follow the [evidence integrity runbook](evidence-integrity-mismatch.md). |
| **Compromised `security-workflows` release / action** | Revoke the affected SHAs in `config/trusted-producers.yaml` (emergency PR, 1 approver allowed under incident). Revocation rule for evidence in the compromise window. Notify consumers to bump the pin. Rotate any secrets the affected workflows could access (should be none by design). |
| **Unauthorised data access** | Revoke the sessions and role assignments involved. Rotate the session key if a session store compromise is suspected. Preserve audit logs. Engage the DPO if personal data was involved. |
| **Webhook secret leaked** | Rotate the secret in the App + Key Vault. Review the receiver logs for forged deliveries (forged deliveries can only enqueue hints, so assess for job floods). |
| **Infrastructure compromise** | Isolate the affected Container App (scale to 0 / remove ingress). Redeploy from verified images (attestation check). Rotate all platform credentials. |

### Eradicate and recover
Root cause fixed · credentials rotated · rebuild from IaC and verified images if compromise is suspected · restore data from a verified pre-incident point if needed ([backup plan](../operations/backup-and-restore-plan.md)) · re-run chain verification · unpause ingestion · reconcile from GitHub.

### Post-incident
Review within 5 business days · update the threat model and controls · decision-log entry for any risk accepted · communicate to stakeholders · record the incident as evidence for the platform's own ASC-OPS-02.

## 3. Evidence preservation

Do not delete or modify ledgers (they are immutable anyway). Export the relevant audit events and Sentinel data to the incident case. Snapshot (PITR) before any corrective action. Record every action with a timestamp in the incident ticket.
