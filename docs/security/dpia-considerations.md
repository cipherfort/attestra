# DPIA Considerations

| | |
|---|---|
| Status | DRAFT screening and risk inputs for the DPO. Not a completed DPIA. **REQUIRES DPO REVIEW.** |
| Related | [Privacy assessment](privacy-assessment.md) |

## 1. Screening

| Screening question (typical DPIA triggers) | Answer | Notes |
|---|---|---|
| Systematic monitoring of individuals? | **Possibly** | The platform links security activity (commits, approvals) to identified staff. Mitigated by the team-level-only reporting design, but the capability exists in raw data. |
| Evaluation or scoring of individuals? | No (by design) | Explicitly prohibited. No per-person metrics. |
| Large-scale processing of special-category data? | No | No special-category data about staff. Citizen data is never ingested. |
| New technology? | Partly | Evidence attestation/immutability is novel to the organisation |
| Processing that prevents data-subject rights? | **Partly** | WORM storage prevents early erasure of incidental personal data in raw artefacts |
| Data matching / combining datasets? | Yes | Entra + GitHub + LMS identity linkage |
| Vulnerable data subjects? | No | |

**Indicative conclusion:** two or more triggers are present (monitoring potential, combining datasets, limits on erasure), so **a DPIA is recommended**. The DPO decides.

## 2. Risks to individuals and mitigations

| # | Risk to individuals | Likelihood / severity (pre) | Mitigation | Residual |
|---|---|---|---|---|
| P1 | Platform data used to judge individual performance (blame for vulnerabilities) | Medium / Medium | Prohibited-use policy. No per-person views. Team-level metrics. Champion recognition input is self-supplied. Governance oversight. | Low |
| P2 | Exposure of the identity of the developer who leaked a secret, beyond those who need to know | Medium / Low | Committer identity kept only in raw artefacts (restricted access). Normalised findings show repo/file, not author. | Low |
| P3 | Excessive retention of staff identities | Medium / Low | Retention schedule. Leaver pseudonymisation. Minimised Entra sync. | Low |
| P4 | Inability to erase data on request (WORM) | Low / Low | Minimisation before WORM. Documented limitation. Retention periods proportionate. | Low–Medium (accept with DPO) |
| P5 | Breach of the platform exposes staff identities alongside vulnerability data | Low / Medium | Platform security architecture, private networking, RBAC/RLS, monitoring | Low |
| P6 | External contributors' data (public repos) processed without awareness | Low / Low | Privacy notice reference in SECURITY.md / CONTRIBUTING (to agree) | Low |

## 3. Consultation

DPO · Information Governance · HR/employee relations (monitoring concern) · trade union / staff representatives if required by organisational policy · SOC (data sharing).

## 4. Actions before go-live (pilot)

1. DPO screening decision recorded (decision log).
2. Lawful basis documented.
3. Privacy notice for platform users and engineers published.
4. Record of processing activities updated.
5. Retention policy approved (ADR-017), then WORM locked.
