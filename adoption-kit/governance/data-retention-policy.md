# Data Retention Policy: Attestra

| | |
|---|---|
| Status | DRAFT. **REQUIRES HUMAN APPROVAL** (records management, DPO, internal audit). Not a statement of legal compliance. |
| Owner | Head of Application Security (data owner); platform team (operator) |
| Decision record | [ADR-017](../../adr/ADR-017-evidence-retention.md) |

## 1. Scope

All data held by the platform: PostgreSQL records, Blob evidence storage, logs and telemetry, backups and archives, and data exported to Sentinel/Jira.

## 2. Retention schedule

| Data category | Contains personal data? | Online | Archive | Disposal method | Basis for period (to confirm) |
|---|---|---|---|---|---|
| Evidence records, control evaluations | Limited (actor IDs) | 24 months | to 7 years | Partition export → verify chain → detach/drop. Archive deleted at expiry. | Audit and investigation needs. Organisational records schedule. |
| Raw scan artefacts, SBOMs | Limited (committer identities inside raw output) | n/a | 3 years WORM | WORM expiry → lifecycle delete | CVE-response value declines after 3 years |
| Manual assessment artefacts (pen test, architecture review) | Limited | n/a | 7 years WORM | WORM expiry → delete | Formal assurance records |
| Audit events | Yes (actor, IP) | 24 months | to 7 years | As evidence | Security audit trail |
| Findings (open) | Limited | While open | — | — | Operational |
| Findings (closed / false positive) | Limited | 3 years after closure | Aggregates only | Scheduled job | Trend and recurrence analysis |
| Exceptions | Yes (requester, approver) | Life + 3 years | to 7 years | As evidence | Risk-acceptance accountability |
| Maturity snapshots | No | Indefinite | — | — | Small, non-personal, long-term trend |
| Users (registry) | Yes | While active | — | Pseudonymised 90 days after deactivation | Minimisation |
| Training records | Yes | Current + 1 previous completion | — | Scheduled job | Coverage computation only |
| Application telemetry / logs | Possibly (IPs, IDs) | 90 days (Log Analytics) | — | Workspace retention | Operations |
| Jobs, outbox, webhook delivery IDs | No | 7–30 days | — | Scheduled job | Operational only |
| Backups (PITR) | As source | 35 days | Monthly long-term 12 months | Platform-managed expiry | Recovery (ADR-026) |
| Sentinel copies of events/checkpoints | Limited | Per SOC policy, ≥ evidence retention for checkpoints | — | SOC | Tamper-evidence anchor |

## 3. Rules

| ID | Rule |
|---|---|
| RET-01 | Immutable (WORM) retention policies stay **unlocked** until this policy is approved. Locking is a change-controlled action with two-person approval. |
| RET-02 | Personal data is minimised **before** it enters WORM storage (secret values redacted; normalised records strip committer emails where not needed), because WORM data cannot be erased early |
| RET-03 | Legal hold: the Head of AppSec, on Legal instruction, may suspend disposal for named data. Holds are recorded in the decision log. |
| RET-04 | Data subject requests are handled via the DPO. Erasure inside WORM artefacts may not be possible before expiry. This limitation is recorded in the DPIA. |
| RET-05 | Disposal jobs log what was disposed (category, partition, count), never the content |
| RET-06 | This policy is reviewed annually and on any change to the organisational records schedule |
