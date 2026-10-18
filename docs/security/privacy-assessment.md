# Privacy / Data Protection Assessment: FortProof

| | |
|---|---|
| Status | DRAFT input for the DPO. **Does not claim compliance with UK GDPR, the Data Protection Act 2018 or any other law.** Legal and DPO review is required. |
| Owner | Programme owner, with the DPO |
| Companion | [DPIA considerations](dpia-considerations.md), [Data Retention Policy](../../adoption-kit/governance/data-retention-policy.md) |

## 1. Does the platform process personal data?

**Yes, in limited categories.** It is primarily a security-assurance system about applications, but it necessarily processes data about the people who build, own and assess them.

| Category | Examples | Data subjects | Source | Necessity |
|---|---|---|---|---|
| Identity of owners and roles | Names, work emails, Entra object IDs, GitHub logins of business/technical owners, champions | Staff, contractors | `application.yaml`, Entra, GitHub | Required for ownership and escalation |
| Workflow actors | Requester/approver of exceptions, reviewers, assessors | Staff | Platform sessions | Required for SoD and accountability |
| Audit records | Actor, action, time, source IP, user agent | Platform users | API | Required for security of the platform |
| Developer activity inside raw artefacts | Commit author names/emails in scanner output, committer of an exposed secret | Developers, external contributors (public repos) | Scanner output | Incidental. Minimised in normalised records. |
| Training completion | Course completion dates | Engineers | LMS export | Team-level coverage only |
| Security findings | Vulnerabilities in applications | Not personal data in themselves | Scanners | Core purpose |
| **Application data** | Citizen data processed by the applications | — | **Not processed.** The platform never ingests application data. | — |

## 2. Purposes

Security assurance of applications · risk management and remediation tracking · audit of security controls · platform security (audit logging). **Explicitly excluded purpose: monitoring or evaluating individual employee performance.** Per-person metrics are not built, and team-level reporting is the minimum granularity.

## 3. Data protection by design measures

| Measure | Implementation |
|---|---|
| Minimisation | Secret values are never stored. Committer emails are stripped from normalised findings. Only the attributes needed for ownership are synced from Entra. |
| Purpose limitation | Prohibited-use statement in the charter and acceptable-use notice. No individual leaderboards. |
| Access control | RBAC + RLS. Auditor access time-bound. Admins lack default detail access. ([Access Control Model](access-control-model.md)) |
| Retention | Defined per category. Leavers pseudonymised after 90 days. ([Retention Policy](../../adoption-kit/governance/data-retention-policy.md)) |
| Security | Private networking, encryption in transit/at rest, immutable audit, threat model ([platform security](platform-security-architecture.md)) |
| Transparency | Privacy notice for platform users and engineers (to draft with the DPO) |
| Data location | Azure UK South (primary), UK West (backup/DR). No transfer outside the UK expected. **Confirm for Sentinel, GitHub and Jira, which are SaaS.** |

## 4. Points requiring DPO / Legal determination

1. **Lawful basis** for processing staff data in this platform (likely legitimate interests or public task, depending on organisation type). This needs a DPO determination; this document does not decide it.
2. Whether processing of **external contributor data** in raw artefacts of public repos needs specific notice.
3. Whether **WORM retention** (data that cannot be erased early) is acceptable for incidental personal data, with the minimisation measures above.
4. Whether a **full DPIA** is required. See the screening in [DPIA considerations](dpia-considerations.md). A conservative reading suggests one is advisable, given systematic processing linked to employees' work.
5. Employee consultation or works-council requirements, if applicable.
6. Data sharing with the SOC (Sentinel) and Jira: confirm these are within existing processing records.
