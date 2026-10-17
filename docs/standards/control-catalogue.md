# Control Catalogue (rendered)

> **Generated** from `catalogue/controls/controls.yaml` by `tools/catalogue/validate.py`. Do not edit by hand.  
> Catalogue version **0.1.0**: status DESIGNED, REQUIRES HUMAN APPROVAL.  
> Tier columns: **M** mandatory · **R** recommended · **–** not applicable.  
> Mappings are framework references. Control wording, thresholds and evidence rules are organisation-specific.

**48 controls**: 37 automated, 7 hybrid, 4 manual.

## Summary

| ID | Control | Type | T1 | T2 | T3 | T4 | Mode | Min confidence | Evidence | SAMM | SSDF |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [ASC-GOV-01](#asc-gov-01) | Application is registered with accountable owners | configuration | M | M | M | M | automated | C1 | registry.application | D-TA-A1 | PO.2.1 |
| [ASC-GOV-02](#asc-gov-02) | Application classification is current and approved | process | M | M | M | M | hybrid | T1:M2 / T2:M2 / T3:M1 / T4:M1 | registry.classification | D-TA-A2, D-TA-A3 |  |
| [ASC-GOV-03](#asc-gov-03) | Security champion assigned and trained | process | M | M | R | – | automated | C1 | registry.application, training.completion | G-EG-B1 | PO.2.1, PO.2.2 |
| [ASC-GOV-04](#asc-gov-04) | Engineers have completed secure development training | outcome | M | M | R | R | automated | C3 | training.completion | G-EG-A1, G-EG-A2 | PO.2.2 |
| [ASC-GOV-05](#asc-gov-05) | Security contact and vulnerability disclosure route published | configuration | M | M | M | R | automated | C1 | registry.application | O-IM-B1 | RV.1.3 |
| [ASC-REQ-01](#asc-req-01) | ASVS target level and applicability profile defined | configuration | M | M | M | R | automated | C1 | registry.application | D-SR-A1 | PO.1.2, PW.1.2 |
| [ASC-REQ-02](#asc-req-02) | Applicable ASVS requirements have a verification status | outcome | M | M | R | – | hybrid | C2 | test.security, scan.sast, scan.dast, scan.api, assessment.manual_control | D-SR-A2, V-RT-A1 | PW.1.2, PO.4.1 |
| [ASC-REQ-03](#asc-req-03) | Supplier and third-party service security requirements recorded | process | M | R | – | – | manual | M2 | assessment.manual_control | D-SR-B1, D-SR-B2 | PO.1.3 |
| [ASC-TM-01](#asc-tm-01) | Threat model exists, is structured, and has been reviewed | process | M | M | R | – | hybrid | T1:M2 / T2:M2 / T3:M1 | repo.threat_model, assessment.threat_model | D-TA-B1, D-TA-B2 | PW.1.1 |
| [ASC-TM-02](#asc-tm-02) | Threat model is current | process | M | M | R | – | hybrid | M1 | assessment.threat_model | D-TA-B2, D-TA-B3 | PW.1.1 |
| [ASC-TM-03](#asc-tm-03) | Threats are mitigated, linked or accepted | outcome | M | R | – | – | automated | C1 | repo.threat_model | D-TA-B3, V-AA-B1 | PW.1.2 |
| [ASC-ARC-01](#asc-arc-01) | Architecture security review completed | process | M | M | R | – | manual | M2 | assessment.architecture_review | V-AA-A1, V-AA-A2 | PW.2.1 |
| [ASC-ARC-02](#asc-arc-02) | No end-of-life runtimes or frameworks | outcome | M | M | M | R | automated | C2 | sbom, scan.container, sbom.eol | D-SA-B2, O-EM-B2 | PW.4.1 |
| [ASC-ARC-03](#asc-arc-03) | Architecture review findings tracked to closure | outcome | M | M | R | – | automated | C3 | vuln.posture | V-AA-B1, V-AA-B2 | RV.2.2 |
| [ASC-SRC-01](#asc-src-01) | Default branch protected | configuration | M | M | M | R | automated | C1 | repo.ruleset | I-SB-A2 | PS.1.1, PW.7.2 |
| [ASC-SRC-02](#asc-src-02) | CODEOWNERS covers security-sensitive paths | configuration | M | M | R | – | automated | C1 | repo.codeowners | I-SB-A2 | PS.1.1 |
| [ASC-SRC-03](#asc-src-03) | Secret scanning and push protection enabled | configuration | M | M | M | M | automated | C1 | repo.security_settings | I-SD-B1 | PW.7.2, PS.1.1 |
| [ASC-SRC-04](#asc-src-04) | No active exposed secrets | outcome | M | M | M | M | automated | C3 | scan.secrets | I-SD-B2 | RV.2.2 |
| [ASC-SRC-05](#asc-src-05) | Repository access is least-privilege and visibility is approved | configuration | M | M | M | R | automated | C1 | repo.access | I-SB-A1 | PS.1.1 |
| [ASC-SRC-06](#asc-src-06) | GitHub Actions workflows are hardened | outcome | M | M | M | R | automated | C2 | scan.workflow_hardening, repo.actions_policy | I-SB-A2, I-SB-B2 | PO.3.2, PO.5.1 |
| [ASC-BLD-01](#asc-bld-01) | SAST executes on every change to the default branch | activity | M | M | M | R | automated | C2 | scan.sast | V-ST-A1, I-SB-A2 | PW.7.2 |
| [ASC-BLD-02](#asc-bld-02) | Dependency vulnerability analysis (SCA) executes | activity | M | M | M | M | automated | C2 | scan.sca | I-SB-B2 | PW.4.4, RV.1.1 |
| [ASC-BLD-03](#asc-bld-03) | SBOM generated for every release artifact and ingested | activity | M | M | M | R | automated | C2 | sbom | I-SB-B1 | PS.3.2 |
| [ASC-BLD-04](#asc-bld-04) | IaC is scanned for misconfiguration | activity | M | M | M | R | automated | C2 | scan.iac | O-EM-A2, I-SB-A2 | PW.7.2, PW.9.1 |
| [ASC-BLD-05](#asc-bld-05) | Container images are scanned by digest | activity | M | M | M | R | automated | C2 | scan.container, sbom | I-SB-B2, O-EM-B2 | PW.4.4, RV.1.1 |
| [ASC-BLD-06](#asc-bld-06) | Release artifacts carry verified build provenance | activity | M | M | R | – | automated | C3 | provenance.attestation | I-SB-A3 | PS.2.1, PS.3.1 |
| [ASC-BLD-07](#asc-bld-07) | Dependency review gates new vulnerable or disallowed dependencies | configuration | M | M | R | – | automated | C2 | repo.ruleset, scan.sca | I-SB-B3 | PW.4.1 |
| [ASC-BLD-08](#asc-bld-08) | Licence policy compliance | outcome | M | M | M | R | automated | C2 | scan.licence | I-SB-B2, G-PC-B2 | PW.4.1 |
| [ASC-BLD-09](#asc-bld-09) | No malicious or compromised packages | outcome | M | M | M | M | automated | C2 | scan.malicious_package, sbom | I-SB-B3 | PW.4.4 |
| [ASC-DEP-01](#asc-dep-01) | Production deployments only through protected pipeline environments | configuration | M | M | R | – | automated | C1 | repo.environments, deploy.record | I-SD-A1, I-SD-A2 | PO.5.1 |
| [ASC-DEP-02](#asc-dep-02) | No long-lived cloud credentials in CI | configuration | M | M | M | R | automated | C1 | repo.environments, scan.workflow_hardening | I-SD-B2 | PO.5.1 |
| [ASC-DEP-03](#asc-dep-03) | Artifact integrity verified at deployment | activity | M | R | – | – | automated | C2 | deploy.record | I-SD-A3 | PS.2.1 |
| [ASC-DEP-04](#asc-dep-04) | Application runtime secrets held in a managed vault | configuration | M | M | R | – | hybrid | C2 | scan.iac, cloud.posture | I-SD-B2, I-SD-B3 | PO.5.1 |
| [ASC-TST-01](#asc-tst-01) | DAST executes against a deployed environment | activity | M | M | R | – | automated | C2 | scan.dast, deploy.record | V-ST-A2 | PW.8.2 |
| [ASC-TST-02](#asc-tst-02) | API security testing against the API definition | activity | M | M | R | – | automated | C2 | scan.api | V-ST-A2, V-RT-B2 | PW.8.2 |
| [ASC-TST-03](#asc-tst-03) | Independent penetration test within period | process | M | M | R | – | manual | M2 | assessment.pentest | V-ST-B2 | PW.8.2 |
| [ASC-TST-04](#asc-tst-04) | Abuse-case tests derived from the threat model | activity | M | R | – | – | automated | C2 | test.security, repo.threat_model | V-RT-B2, V-RT-A3 | PW.8.2 |
| [ASC-TST-05](#asc-tst-05) | Security regression tests run in CI | activity | M | M | R | – | automated | C2 | test.security | V-RT-A2, V-RT-A3 | PW.8.2 |
| [ASC-VUL-01](#asc-vul-01) | Findings are owned and triaged within SLA | outcome | M | M | M | M | automated | C3 | vuln.posture | I-DM-A1, I-DM-A2 | RV.2.1 |
| [ASC-VUL-02](#asc-vul-02) | Vulnerabilities remediated within SLA | outcome | M | M | M | M | automated | C3 | vuln.posture | I-DM-A2, I-DM-A3 | RV.2.2 |
| [ASC-VUL-03](#asc-vul-03) | Exceptions are approved, current and within limits | outcome | M | M | M | M | automated | C3 | vuln.posture | G-PC-B2, I-DM-A2 |  |
| [ASC-VUL-04](#asc-vul-04) | Recurring weakness classes are analysed | process | M | R | – | – | hybrid | M1 | process.review_record | I-DM-B2, I-DM-B3 | RV.3.1, RV.3.2, RV.3.3 |
| [ASC-OPS-01](#asc-ops-01) | Security-relevant application logs reach the SIEM | activity | M | M | R | – | automated | C3 | siem.log_source_health | O-IM-A1, O-IM-A2 |  |
| [ASC-OPS-02](#asc-ops-02) | Incident response readiness for the application | process | M | R | – | – | manual | T1:M2 / T2:M1 | assessment.manual_control | O-IM-B1, O-IM-B2 |  |
| [ASC-OPS-03](#asc-ops-03) | Cloud posture findings on the application's scopes are within SLA | outcome | M | M | R | – | automated | C3 | cloud.posture | O-EM-A2, O-EM-A3 |  |
| [ASC-OPS-04](#asc-ops-04) | Deployed images and runtimes are patched regularly | outcome | M | M | R | – | automated | C2 | deploy.record, scan.container | O-EM-B1, O-EM-B2 |  |
| [ASC-OPS-05](#asc-ops-05) | Data stores are inventoried, encrypted and backed up per classification | configuration | M | R | – | – | hybrid | C1 | cloud.posture, registry.application | O-OM-A1, O-OM-A2 |  |
| [ASC-OPS-06](#asc-ops-06) | Retired applications are fully decommissioned | outcome | M | M | M | M | automated | C1 | repo.access, cloud.posture | O-OM-B1, O-OM-B2 |  |

## SAMM coverage by controls

Which SAMM stream levels have at least one control producing evidence. A gap (·) means that activity can only be assessed manually (SAMM interview). That is expected for much of Governance.

| Practice | Stream | L1 | L2 | L3 |
|---|---|---|---|---|
| Governance / Strategy & Metrics | G-SM-A Create and Promote | · | · | · |
| Governance / Strategy & Metrics | G-SM-B Measure and Improve | · | · | · |
| Governance / Policy & Compliance | G-PC-A Policy and Standards | · | · | · |
| Governance / Policy & Compliance | G-PC-B Compliance Management | · | ASC-BLD-08, ASC-VUL-03 | · |
| Governance / Education & Guidance | G-EG-A Training and Awareness | ASC-GOV-04 | ASC-GOV-04 | · |
| Governance / Education & Guidance | G-EG-B Organization and Culture | ASC-GOV-03 | · | · |
| Design / Threat Assessment | D-TA-A Application Risk Profile | ASC-GOV-01 | ASC-GOV-02 | ASC-GOV-02 |
| Design / Threat Assessment | D-TA-B Threat Modeling | ASC-TM-01 | ASC-TM-01, ASC-TM-02 | ASC-TM-02, ASC-TM-03 |
| Design / Security Requirements | D-SR-A Software Requirements | ASC-REQ-01 | ASC-REQ-02 | · |
| Design / Security Requirements | D-SR-B Supplier Security | ASC-REQ-03 | ASC-REQ-03 | · |
| Design / Secure Architecture | D-SA-A Architecture Design | · | · | · |
| Design / Secure Architecture | D-SA-B Technology Management | · | ASC-ARC-02 | · |
| Implementation / Secure Build | I-SB-A Build Process | ASC-SRC-05 | ASC-BLD-01, ASC-BLD-04, ASC-SRC-01, ASC-SRC-02, ASC-SRC-06 | ASC-BLD-06 |
| Implementation / Secure Build | I-SB-B Software Dependencies | ASC-BLD-03 | ASC-BLD-02, ASC-BLD-05, ASC-BLD-08, ASC-SRC-06 | ASC-BLD-07, ASC-BLD-09 |
| Implementation / Secure Deployment | I-SD-A Deployment Process | ASC-DEP-01 | ASC-DEP-01 | ASC-DEP-03 |
| Implementation / Secure Deployment | I-SD-B Secret Management | ASC-SRC-03 | ASC-DEP-02, ASC-DEP-04, ASC-SRC-04 | ASC-DEP-04 |
| Implementation / Defect Management | I-DM-A Defect Tracking | ASC-VUL-01 | ASC-VUL-01, ASC-VUL-02, ASC-VUL-03 | ASC-VUL-02 |
| Implementation / Defect Management | I-DM-B Metrics and Feedback | · | ASC-VUL-04 | ASC-VUL-04 |
| Verification / Architecture Assessment | V-AA-A Architecture Validation | ASC-ARC-01 | ASC-ARC-01 | · |
| Verification / Architecture Assessment | V-AA-B Architecture Mitigation | ASC-ARC-03, ASC-TM-03 | ASC-ARC-03 | · |
| Verification / Requirements-driven Testing | V-RT-A Control Verification | ASC-REQ-02 | ASC-TST-05 | ASC-TST-04, ASC-TST-05 |
| Verification / Requirements-driven Testing | V-RT-B Misuse/Abuse Testing | · | ASC-TST-02, ASC-TST-04 | · |
| Verification / Security Testing | V-ST-A Scalable Baseline | ASC-BLD-01 | ASC-TST-01, ASC-TST-02 | · |
| Verification / Security Testing | V-ST-B Deep Understanding | · | ASC-TST-03 | · |
| Operations / Incident Management | O-IM-A Incident Detection | ASC-OPS-01 | ASC-OPS-01 | · |
| Operations / Incident Management | O-IM-B Incident Response | ASC-GOV-05, ASC-OPS-02 | ASC-OPS-02 | · |
| Operations / Environment Management | O-EM-A Configuration Hardening | · | ASC-BLD-04, ASC-OPS-03 | ASC-OPS-03 |
| Operations / Environment Management | O-EM-B Patching and Updating | ASC-OPS-04 | ASC-ARC-02, ASC-BLD-05, ASC-OPS-04 | · |
| Operations / Operational Management | O-OM-A Data Protection | ASC-OPS-05 | ASC-OPS-05 | · |
| Operations / Operational Management | O-OM-B System Decommissioning / Legacy Management | ASC-OPS-06 | ASC-OPS-06 | · |

## Control detail

### ASC-GOV-01

**Application is registered with accountable owners** · domain `GOV` · configuration · owner `appsec-governance` · review every 12 months

The application has a schema-valid .security/application.yaml in its primary repository (or a registry entry for apps without a repo). Business owner and technical owner resolve to active identities, and every repository implementing the app is linked.

- **Rationale:** Without ownership and linkage nothing else can be attributed, prioritised or escalated.
- **Applies when:** always
- **Assessment:** automated · evaluator `registry_complete@1` · min confidence C1 · evidence `registry.application`
- **Parameters:** `{max_unlinked_repos: 0, owners_must_resolve: true}`
- **How we prove it operates:** The GitHub connector reads application.yaml daily and on push, validates it against the schema, and resolves owners against Entra ID and GitHub teams. Departed owners fail the control within 24h.
- **Implementation:** Merge the onboarding PR raised by the platform; complete owner and classification fields.
- **Remediation:** Update owners in application.yaml; the control re-evaluates on push.
- **Exceptions:** not permitted
- **Mappings:** SAMM: D-TA-A L1 · SSDF: PO.2.1 · CSF 2.0: ID.AM-02, GV.RR-02

### ASC-GOV-02

**Application classification is current and approved** · domain `GOV` · process · owner `appsec-governance` · review every 12 months

The tier is computed by the classification model from current inputs, approved by AppSec for Tier 1/2, and reviewed at least every 12 months or when a classification input changes.

- **Rationale:** The tier determines every other control requirement; a stale tier silently under-protects.
- **Applies when:** always
- **Assessment:** hybrid · evaluator `classification_current@1` · min confidence T1:M2 / T2:M2 / T3:M1 / T4:M1 · evidence `registry.classification`
- **How we prove it operates:** The classification record stores inputs, model version, computed tier, approver and date. The event_bound freshness policy invalidates it when application.yaml classification inputs change.
- **Implementation:** Answer the classification questions in application.yaml; AppSec approves Tier 1/2 in the platform.
- **Remediation:** Re-attest classification in the platform; changes in tier re-baseline required controls.
- **Exceptions:** not permitted
- **Mappings:** SAMM: D-TA-A L2, D-TA-A L3 · CSF 2.0: ID.AM-05

### ASC-GOV-03

**Security champion assigned and trained** · domain `GOV` · process · owner `appsec-governance` · review every 12 months

The owning team has a named security champion who has completed champion onboarding within 12 months.

- **Rationale:** Champions are the scaling mechanism for threat modelling, triage and guidance.
- **Applies when:** always
- **Assessment:** automated · evaluator `champion_assigned@1` · min confidence C1 · evidence `registry.application`, `training.completion`
- **Parameters:** `{training_course: champion-onboarding, within_days: 365}`
- **How we prove it operates:** Champion field in application.yaml resolved to an active user, and an LMS completion record for the champion course.
- **Implementation:** Nominate a champion; enrol them in the champion programme.
- **Remediation:** Nominate a replacement within 30 days of a champion leaving.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: G-EG-B L1 · SSDF: PO.2.1, PO.2.2 · CSF 2.0: PR.AT-02

### ASC-GOV-04

**Engineers have completed secure development training** · domain `GOV` · outcome · owner `appsec-governance` · review every 12 months

At least 90% of engineers contributing to the app's repositories in the last 90 days hold a current secure-development training completion.

- **Rationale:** Baseline awareness reduces the introduction rate of common weakness classes.
- **Applies when:** always
- **Assessment:** automated · evaluator `team_training_coverage@1` · min confidence C3 · evidence `training.completion`
- **Parameters:** `{contributor_window_days: 90, threshold_pct: 90}`
- **How we prove it operates:** LMS completion export (connector) joined to GitHub contributors via the Entra/GitHub identity link. Reported at TEAM level only, never per person (privacy, see platform security architecture §6).
- **Implementation:** Assign the secure-development course to all engineers via the LMS.
- **Remediation:** Team lead schedules outstanding completions.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: G-EG-A L1, G-EG-A L2 · SSDF: PO.2.2 · CSF 2.0: PR.AT-01, PR.AT-02
- **Notes:** LMS connector is PROPOSED; until it exists this control is evaluated from a quarterly HR export (M1).

### ASC-GOV-05

**Security contact and vulnerability disclosure route published** · domain `GOV` · configuration · owner `appsec-governance` · review every 12 months

The repository contains SECURITY.md (or org default) describing how to report vulnerabilities, and .security/security-contact.yaml names a monitored contact.

- **Rationale:** External and internal reporters need a working route; SSDF RV.1.3.
- **Applies when:** always
- **Assessment:** automated · evaluator `security_policy_present@1` · min confidence C1 · evidence `registry.application`
- **How we prove it operates:** GitHub API community profile reports a security policy; contact address resolves to a monitored mailbox/group.
- **Implementation:** Inherit the org-level SECURITY.md from the .github repository; add security-contact.yaml.
- **Remediation:** Add the file; re-evaluates on push.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-IM-B L1 · SSDF: RV.1.3 · CSF 2.0: ID.RA-08

### ASC-REQ-01

**ASVS target level and applicability profile defined** · domain `REQ` · configuration · owner `appsec-governance` · review every 12 months

.security/asvs.yaml declares the ASVS version and target level (≥ the tier's asvs_target) and the applicability profile (web UI, API, OAuth/OIDC, file handling, WebRTC, ...) used to scope requirements.

- **Rationale:** Makes the requirement set explicit and machine-scoped instead of a 300-line checklist.
- **Applies when:** always
- **Assessment:** automated · evaluator `asvs_profile_valid@1` · min confidence C1 · evidence `registry.application`
- **How we prove it operates:** Schema validation plus check target_level ≥ classification asvs_target.
- **Implementation:** Generated by onboarding from application.yaml capability flags; team reviews.
- **Remediation:** Raise target level or approve a tier override.
- **Exceptions:** not permitted
- **Mappings:** SAMM: D-SR-A L1 · ASVS 5.0: V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17 · SSDF: PO.1.2, PW.1.2

### ASC-REQ-02

**Applicable ASVS requirements have a verification status** · domain `REQ` · outcome · owner `appsec-governance` · review every 12 months

Every applicable ASVS requirement for the target level has a status of verified (by automated test, scanner rule, or manual review evidence), not-verified, or excepted. Target: ≥ 80% verified for Tier 1/2.

- **Rationale:** Turns ASVS into tracked, evidenced requirements rather than a one-off checklist.
- **Applies when:** always
- **Assessment:** hybrid · evaluator `asvs_coverage@1` · min confidence C2 · evidence `test.security`, `scan.sast`, `scan.dast`, `scan.api`, `assessment.manual_control`
- **Parameters:** `{verified_pct: {'1': 80, '2': 80, '3': 50}}`
- **How we prove it operates:** Requirement status is DERIVED from evidence: JUnit tests carrying an asvs property, scanner rules mapped to ASVS requirements, and manual review records. A requirement cannot be marked verified by hand.
- **Implementation:** Tag security tests with ASVS IDs; use the test-evidence workflow; book manual review for the rest.
- **Remediation:** Add tests or manual verification for unverified requirements, prioritised by threat model.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-SR-A L2, V-RT-A L1 · SSDF: PW.1.2, PO.4.1 · CSF 2.0: PR.PS-06

### ASC-REQ-03

**Supplier and third-party service security requirements recorded** · domain `REQ` · process · owner `appsec-governance` · review every 12 months

Third-party services and suppliers listed in application.yaml have a recorded security assessment or contract security schedule reference.

- **Rationale:** SaaS and supplier components are part of the attack surface but invisible to code scanning.
- **Applies when:** has_third_party_services
- **Assessment:** manual · evaluator `manual_attestation@1` · min confidence M2 · evidence `assessment.manual_control`
- **How we prove it operates:** Procurement/supplier-assurance reference recorded per supplier and reviewed by Security Governance.
- **Implementation:** List suppliers in application.yaml; link supplier assurance records.
- **Remediation:** Request supplier assessment through procurement.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-SR-B L1, D-SR-B L2 · SSDF: PO.1.3 · CSF 2.0: GV.SC-05, GV.SC-07

### ASC-TM-01

**Threat model exists, is structured, and has been reviewed** · domain `TM` · process · owner `appsec-governance` · review every 12 months

.security/threat-model/ contains a schema-valid model (system context, data flows, trust boundaries, assets, threats with STRIDE category, mitigations, residual risk) and a review is recorded.

- **Rationale:** Design-level threats cannot be found by scanners.
- **Applies when:** always
- **Assessment:** hybrid · evaluator `threat_model_reviewed@1` · min confidence T1:M2 / T2:M2 / T3:M1 · evidence `repo.threat_model`, `assessment.threat_model`
- **How we prove it operates:** Structural validity is automated (C1). "Reviewed" requires a review record by a reviewer outside the team for Tier 1/2 (M2), bound to the commit SHA of the threat-model files reviewed.
- **Implementation:** Use the threat-model kit (docs/standards/threat-modelling-standard.md); book AppSec facilitation for Tier 1.
- **Remediation:** Complete or update the model; request review in the platform.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-TA-B L1, D-TA-B L2 · SSDF: PW.1.1 · CSF 2.0: ID.RA-04, ID.RA-05

### ASC-TM-02

**Threat model is current** · domain `TM` · process · owner `appsec-governance` · review every 12 months

The reviewed threat model is within its review period and no architecture-change event has occurred since review.

- **Rationale:** Stale threat models give false assurance.
- **Applies when:** always
- **Assessment:** hybrid · evaluator `evidence_fresh@1` · min confidence M1 · evidence `assessment.threat_model`
- **Parameters:** `{architecture_change_signals: ['PR label: architecture-change', change to .security/threat-model/data-flow*, new internet exposure in application.yaml, new data store in application.yaml]}`
- **How we prove it operates:** Freshness engine; event_bound invalidation from the listed signals.
- **Implementation:** Label architecture-changing PRs; update data-flow on change.
- **Remediation:** Re-review the threat model.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-TA-B L2, D-TA-B L3 · SSDF: PW.1.1

### ASC-TM-03

**Threats are mitigated, linked or accepted** · domain `TM` · outcome · owner `appsec-governance` · review every 12 months

Every threat rated high in threats.yaml links to a mitigation (control/requirement/ticket) or an approved residual-risk acceptance.

- **Rationale:** A threat model that lists threats but tracks nothing is documentation, not risk management.
- **Applies when:** always
- **Assessment:** automated · evaluator `threat_mitigation_linkage@1` · min confidence C1 · evidence `repo.threat_model`
- **How we prove it operates:** Parser checks every high threat has mitigation refs that resolve (ASVS ID, ASC control, Jira key) or a residual-risk entry with approved exception ID.
- **Implementation:** Reference mitigations by ID in mitigations.yaml.
- **Remediation:** Link or raise mitigation tickets.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-TA-B L3, V-AA-B L1 · SSDF: PW.1.2 · CSF 2.0: ID.RA-06

### ASC-ARC-01

**Architecture security review completed** · domain `ARC` · process · owner `appsec-governance` · review every 12 months

An architecture security review has been completed before first production release and after every material architecture change.

- **Rationale:** Catches design flaws (authN/authZ model, trust boundaries, data flows) that are expensive to fix later.
- **Applies when:** always
- **Assessment:** manual · evaluator `manual_attestation@1` · min confidence M2 · evidence `assessment.architecture_review`
- **How we prove it operates:** Review record (reviewer, scope, commit of design docs, outcome, findings imported as findings) in the platform; independent reviewer enforced.
- **Implementation:** Request a review via the platform; provide threat model and architecture docs.
- **Remediation:** Address review findings; request re-review.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-AA-A L1, V-AA-A L2 · SSDF: PW.2.1 · CSF 2.0: ID.RA-05

### ASC-ARC-02

**No end-of-life runtimes or frameworks** · domain `ARC` · outcome · owner `appsec-governance` · review every 12 months

No component in the current SBOM or deployed image is a runtime, framework or OS past its end-of-life date.

- **Rationale:** EOL components stop receiving security fixes; vulnerability scanners under-report them.
- **Applies when:** has_sbom_capable_stack
- **Assessment:** automated · evaluator `eol_components@1` · min confidence C2 · evidence `sbom`, `scan.container`, `sbom.eol`
- **Parameters:** `{eol_source: endoflife.date (config/eol-products.yaml), grace_days: 0}`
- **How we prove it operates:** SBOM components matched against cached EOL data; result recorded as derived evidence with the data snapshot date.
- **Implementation:** Keep runtimes on supported versions; plan upgrades ahead of EOL (warning at 180 days).
- **Remediation:** Upgrade, or raise a time-bound exception with a migration plan.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: D-SA-B L2, O-EM-B L2 · SSDF: PW.4.1 · CSF 2.0: PR.PS-02

### ASC-ARC-03

**Architecture review findings tracked to closure** · domain `ARC` · outcome · owner `appsec-governance` · review every 12 months

Findings from architecture reviews are recorded as platform findings and remediated within SLA or excepted.

- **Rationale:** Closes the loop between assessment and mitigation.
- **Applies when:** always
- **Assessment:** automated · evaluator `findings_within_sla@1` · min confidence C3 · evidence `vuln.posture`
- **Parameters:** `{source: architecture_review}`
- **How we prove it operates:** Derived from finding records with source=architecture_review and their SLA state.
- **Implementation:** Reviewer records findings in the platform during review.
- **Remediation:** Remediate or except.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-AA-B L1, V-AA-B L2 · SSDF: RV.2.2

### ASC-SRC-01

**Default branch protected** · domain `SRC` · configuration · owner `appsec-governance` · review every 12 months

Effective rules on the default branch require a pull request, ≥1 approving review (≥2 for Tier 1), dismissal of stale approvals, code-owner review, required status checks for the mandatory security workflows, and block force-push and deletion. Bypass is limited to a named break-glass team.

- **Rationale:** Guarantees code reaching production was reviewed and passed through the security pipeline.
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `branch_protection@1` · min confidence C1 · evidence `repo.ruleset`
- **Parameters:** `{require_code_owner_review: true, required_approvals: {'1': 2, '2': 1, '3': 1, '4': 1}, required_checks: [aap / sast, aap / sca, aap / secrets]}`
- **How we prove it operates:** The effective rules for the branch are read from GitHub's "rules for a branch" API (rulesets and legacy protection merged). Configuration IS the operating control here; bypass actor list is also checked.
- **Implementation:** Apply the org ruleset "aap-default-branch" (Terraform-managed via the GitHub provider).
- **Remediation:** Opt the repo into the org ruleset.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-A L2 · SSDF: PS.1.1, PW.7.2 · CSF 2.0: PR.PS-01

### ASC-SRC-02

**CODEOWNERS covers security-sensitive paths** · domain `SRC` · configuration · owner `appsec-governance` · review every 12 months

A valid CODEOWNERS file exists; .github/workflows/**, .security/** and IaC paths have owners; GitHub reports no CODEOWNERS errors.

- **Rationale:** Ensures workflow and security-contract changes get the right reviewers (prevents silent removal of scans).
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `codeowners_coverage@1` · min confidence C1 · evidence `repo.codeowners`
- **Parameters:** `{required_paths: [.github/workflows/, .security/]}`
- **How we prove it operates:** GitHub CODEOWNERS errors endpoint + platform path-coverage check.
- **Implementation:** Template CODEOWNERS from the repo template.
- **Remediation:** Add owners for uncovered paths.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-A L2 · SSDF: PS.1.1 · CSF 2.0: PR.AA-05

### ASC-SRC-03

**Secret scanning and push protection enabled** · domain `SRC` · configuration · owner `appsec-governance` · review every 12 months

GHAS secret scanning, push protection and validity checks are enabled for the repository.

- **Rationale:** Prevents credential leaks at the point of push and detects historic leaks.
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `security_feature_enabled@1` · min confidence C1 · evidence `repo.security_settings`
- **Parameters:** `{features: [secret_scanning, secret_scanning_push_protection, secret_scanning_validity_checks]}`
- **How we prove it operates:** security_and_analysis settings from the repos API; push-protection bypasses are separately ingested as findings.
- **Implementation:** Enforced by org security configuration.
- **Remediation:** Enable via the org security configuration.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SD-B L1 · SSDF: PW.7.2, PS.1.1 · CSF 2.0: PR.DS-01

### ASC-SRC-04

**No active exposed secrets** · domain `SRC` · outcome · owner `appsec-governance` · review every 12 months

No open secret-scanning alert for a secret that is (or may be) valid; every alert revoked and closed within P1 SLA.

- **Rationale:** An exposed valid credential is the most directly exploitable finding class.
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `no_open_findings@1` · min confidence C3 · evidence `scan.secrets`
- **Parameters:** `{finding_type: secret, validity: [active, unknown]}`
- **How we prove it operates:** Pulled directly from the secret-scanning alerts API (C3 — authoritative source). Secret values are never stored.
- **Implementation:** Rotate first, then close the alert as revoked.
- **Remediation:** Revoke/rotate the credential; close alert as "revoked".
- **Exceptions:** not permitted
- **Mappings:** SAMM: I-SD-B L2 · SSDF: RV.2.2 · CSF 2.0: ID.RA-06

### ASC-SRC-05

**Repository access is least-privilege and visibility is approved** · domain `SRC` · configuration · owner `appsec-governance` · review every 12 months

No outside collaborators with write/admin; admin limited to ≤ 3 users or a team; public visibility only with an approved open-source record.

- **Rationale:** Limits who can disable controls or exfiltrate code; prevents accidental publication.
- **Applies when:** always
- **Assessment:** automated · evaluator `repo_access_policy@1` · min confidence C1 · evidence `repo.access`
- **Parameters:** `{max_admin_users: 3, public_requires: open_source_approval_id}`
- **How we prove it operates:** Collaborator/team permissions API, visibility; public repos cross-checked against open-source approval records.
- **Implementation:** Manage access through GitHub teams synced from Entra.
- **Remediation:** Remove direct admin grants; request open-source approval or make private.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-A L1 · SSDF: PS.1.1 · CSF 2.0: PR.AA-05

### ASC-SRC-06

**GitHub Actions workflows are hardened** · domain `SRC` · outcome · owner `appsec-governance` · review every 12 months

Workflow static analysis reports no high-severity issues: third-party actions pinned to full SHA, no pull_request_target that checks out untrusted code, top-level permissions declared and minimal, no script injection from untrusted context, no long-lived cloud credentials.

- **Rationale:** CI is a privileged supply-chain entry point (cf. trivy-action tag compromise, Mar 2026).
- **Applies when:** has_workflows
- **Assessment:** automated · evaluator `scan_clean@1` · min confidence C2 · evidence `scan.workflow_hardening`, `repo.actions_policy`
- **Parameters:** `{max_severity: medium}`
- **How we prove it operates:** workflow-lint reusable workflow output (attested) on default branch + org Actions policy settings.
- **Implementation:** Use the org's allowed-actions list; pin by SHA (Dependabot keeps pins current).
- **Remediation:** Apply linter fixes; pin actions.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-A L2, I-SB-B L2 · SSDF: PO.3.2, PO.5.1 · CSF 2.0: GV.SC-04, PR.PS-01

### ASC-BLD-01

**SAST executes on every change to the default branch** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

Static analysis (CodeQL via GHAS by default, or an approved alternative) runs on every push to the default branch and on PRs, covering every language detected in the repository, with the approved query suite.

- **Rationale:** Finds common code-level weakness classes (injection, XSS, unsafe deserialisation) early and cheaply.
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `scan_executed@1` · min confidence C2 · evidence `scan.sast`
- **Parameters:** `{language_coverage: all_detected, query_suite: {'1': security-extended, '2': security-extended, '3': default, '4': default}}`
- **How we prove it operates:** Evidence of an analysis on the current default-branch HEAD (or a commit within the freshness window whose diff to HEAD touches no source paths) from an approved workflow or the GHAS code-scanning analyses API, including tool version, languages and query suite. A workflow file alone is C1 and does NOT satisfy this.
- **Implementation:** Call security-workflows/sast or enable CodeQL default setup; both produce acceptable evidence.
- **Remediation:** Fix failing analysis; add missing languages.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-ST-A L1, I-SB-A L2 · ASVS 5.0: V1, V2, V15 · SSDF: PW.7.2 · CSF 2.0: PR.PS-06

### ASC-BLD-02

**Dependency vulnerability analysis (SCA) executes** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

Resolved dependencies for all detected ecosystems are analysed for known vulnerabilities on each change to dependency manifests/lockfiles and at least every 30 days.

- **Rationale:** Most exploitable vulnerabilities in modern apps are in third-party components.
- **Applies when:** uses_dependencies
- **Assessment:** automated · evaluator `scan_executed@1` · min confidence C2 · evidence `scan.sca`
- **Parameters:** `{ecosystem_coverage: all_detected, require_lockfiles: true}`
- **How we prove it operates:** SCA evidence (approved workflow or Dependabot alerts API) for the current lockfile set; ecosystems compared to repository language/ecosystem detection.
- **Implementation:** Commit lockfiles; call security-workflows/sca.
- **Remediation:** Add lockfiles for unresolved ecosystems.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-B L2 · SSDF: PW.4.4, RV.1.1 · CSF 2.0: ID.RA-01

### ASC-BLD-03

**SBOM generated for every release artifact and ingested** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

A CycloneDX SBOM (SPDX accepted and converted) is generated for each built artifact (source SBOM for repos without artifacts), bound to the artifact digest or commit, and ingested into Dependency-Track.

- **Rationale:** Enables "which apps are affected by CVE-X" and continuous monitoring without re-scanning.
- **Applies when:** uses_dependencies
- **Assessment:** automated · evaluator `sbom_current@1` · min confidence C2 · evidence `sbom`
- **Parameters:** `{bind_to: [artifact_digest, commit], min_components: 1, require_purl_pct: 95}`
- **How we prove it operates:** SBOM evidence with digest binding; ingestion confirmation from Dependency-Track (project UUID, processed timestamp); quality check (purl coverage, component count sanity).
- **Implementation:** Call security-workflows/sbom in the build job that produces the artifact.
- **Remediation:** Fix generator coverage (lockfiles, build context).
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-B L1 · SSDF: PS.3.2 · CSF 2.0: ID.AM-02 · Other: NTIA minimum elements, CycloneDX 1.5+

### ASC-BLD-04

**IaC is scanned for misconfiguration** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

Terraform/Bicep/Kubernetes/Dockerfile content is scanned on each relevant change with the approved policy set.

- **Rationale:** Cloud misconfiguration is a leading cause of breaches and is cheapest to fix pre-deployment.
- **Applies when:** has_iac
- **Assessment:** automated · evaluator `scan_executed@1` · min confidence C2 · evidence `scan.iac`
- **How we prove it operates:** Attested IaC scan output on the commit, with policy-set version.
- **Implementation:** Call security-workflows/iac (Checkov + Trivy config; PSRule for Bicep optional).
- **Remediation:** Fix misconfigurations or record skip with justification (tracked as suppression).
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-EM-A L2, I-SB-A L2 · ASVS 5.0: V13 · SSDF: PW.7.2, PW.9.1 · CSF 2.0: PR.PS-01

### ASC-BLD-05

**Container images are scanned by digest** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

Every image built or deployed for the application is scanned (vulnerabilities + misconfig) by digest at build, and re-evaluated continuously via its SBOM.

- **Rationale:** Base-image and OS-package vulnerabilities are invisible to source SCA.
- **Applies when:** builds_or_deploys_containers
- **Assessment:** automated · evaluator `artifact_scanned@1` · min confidence C2 · evidence `scan.container`, `sbom`
- **Parameters:** `{scope: deployed_digests_or_latest_build}`
- **How we prove it operates:** For each digest in deploy.record (or latest build), a scan evidence record with the same digest exists within freshness.
- **Implementation:** Call security-workflows/container after image build; also generate image SBOM.
- **Remediation:** Rebuild on a patched base image.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-B L2, O-EM-B L2 · SSDF: PW.4.4, RV.1.1 · CSF 2.0: ID.RA-01

### ASC-BLD-06

**Release artifacts carry verified build provenance** · domain `BLD` · activity · owner `appsec-governance` · review every 12 months

Release artifacts (images, packages) have a SLSA build provenance attestation produced by an approved builder, verifiable via the GitHub attestations API / Sigstore.

- **Rationale:** Proves artifacts were built from the stated source by the stated pipeline; defeats artifact substitution.
- **Applies when:** publishes_artifacts
- **Assessment:** automated · evaluator `provenance_verified@1` · min confidence C3 · evidence `provenance.attestation`
- **How we prove it operates:** Platform verifies attestation signature, subject digest, and builder identity (approved reusable workflow).
- **Implementation:** Use actions/attest-build-provenance in the build job (via security-workflows/provenance).
- **Remediation:** Add attestation step; rebuild.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-A L3 · SSDF: PS.2.1, PS.3.1 · CSF 2.0: GV.SC-04 · Other: SLSA Build L2 (L3 with ephemeral, isolated builders)

### ASC-BLD-07

**Dependency review gates new vulnerable or disallowed dependencies** · domain `BLD` · configuration · owner `appsec-governance` · review every 12 months

PRs that introduce dependencies with critical/high known vulnerabilities, malicious-package advisories or denied licences fail a required check.

- **Rationale:** Prevents new risk entering, rather than only detecting existing risk.
- **Applies when:** uses_dependencies
- **Assessment:** automated · evaluator `required_check_configured_and_executing@1` · min confidence C2 · evidence `repo.ruleset`, `scan.sca`
- **Parameters:** `{check_name: aap / dependency-review, min_executions_30d: 1}`
- **How we prove it operates:** The check is required in effective branch rules (C1) AND has executed on at least one PR in 30 days (C2) — configured-but-never-run does not pass.
- **Implementation:** Call security-workflows/dependency-review on pull_request; add to required checks.
- **Remediation:** Enable the required check.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-B L3 · SSDF: PW.4.1 · CSF 2.0: GV.SC-04

### ASC-BLD-08

**Licence policy compliance** · domain `BLD` · outcome · owner `oss-governance` · review every 12 months

No component in the current SBOM has a licence on the organisation's deny list without an approved exception; unknown licences ≤ 5% of components.

- **Rationale:** Legal and open-source governance risk (ADR-029).
- **Applies when:** uses_dependencies
- **Assessment:** automated · evaluator `licence_policy@1` · min confidence C2 · evidence `scan.licence`
- **Parameters:** `{max_unknown_pct: 5, policy: config/licence-policy.yaml}`
- **How we prove it operates:** Platform evaluates SBOM licences against a versioned policy; result is derived evidence.
- **Implementation:** Choose dependencies with approved licences; request OSS approval otherwise.
- **Remediation:** Replace component or obtain legal approval (exception).
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SB-B L2, G-PC-B L2 · SSDF: PW.4.1 · CSF 2.0: GV.SC-05

### ASC-BLD-09

**No malicious or compromised packages** · domain `BLD` · outcome · owner `appsec-governance` · review every 12 months

The resolved dependency set contains no package version listed in malicious-package advisories (OSV MAL-*, GHSA malware).

- **Rationale:** Typosquats and hijacked packages execute at install/build time — before any other control.
- **Applies when:** uses_dependencies
- **Assessment:** automated · evaluator `no_open_findings@1` · min confidence C2 · evidence `scan.malicious_package`, `sbom`
- **Parameters:** `{finding_type: malicious_package}`
- **How we prove it operates:** OSV-based check in SCA workflow + platform re-matching of SBOM inventory against newly published MAL advisories (continuous).
- **Implementation:** Default in security-workflows/sca.
- **Remediation:** Remove the package, rotate any secrets exposed to the build, treat as incident (SOC escalation).
- **Exceptions:** not permitted
- **Mappings:** SAMM: I-SB-B L3 · SSDF: PW.4.4 · CSF 2.0: GV.SC-04, ID.RA-09

### ASC-DEP-01

**Production deployments only through protected pipeline environments** · domain `DEP` · configuration · owner `appsec-governance` · review every 12 months

Production deployment uses a GitHub environment with required reviewers (Tier 1/2), restricted deployment branches, and environment-scoped secrets/OIDC; deployments are recorded.

- **Rationale:** Ensures what runs in production came through the controlled path.
- **Applies when:** deployed_via_github
- **Assessment:** automated · evaluator `environment_protection@1` · min confidence C1 · evidence `repo.environments`, `deploy.record`
- **Parameters:** `{production_env_pattern: ^(prod|production), required_reviewers: {'1': 1, '2': 1}}`
- **How we prove it operates:** Environments API (protection rules, branch policies) + deployments API showing production deployments originate from those environments.
- **Implementation:** Define a production environment; deploy only from it.
- **Remediation:** Add protection rules.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SD-A L1, I-SD-A L2 · SSDF: PO.5.1 · CSF 2.0: PR.PS-01

### ASC-DEP-02

**No long-lived cloud credentials in CI** · domain `DEP` · configuration · owner `appsec-governance` · review every 12 months

CI authenticates to Azure/AWS via OIDC federation; no repository/environment secrets hold cloud client secrets or access keys.

- **Rationale:** Long-lived CI credentials are a top supply-chain exfiltration target.
- **Applies when:** has_cloud_scope
- **Assessment:** automated · evaluator `no_static_cloud_credentials@1` · min confidence C1 · evidence `repo.environments`, `scan.workflow_hardening`
- **Parameters:** `{secret_name_patterns: ['(?i)AZURE_CLIENT_SECRET', '(?i)AWS_SECRET_ACCESS_KEY', '(?i)AZURE_CREDENTIALS']}`
- **How we prove it operates:** Secret NAMES (never values) from repo/environment secrets API + workflow analysis for credential-based login actions.
- **Implementation:** Use OIDC federation from the pipeline to the cloud; never stored cloud keys.
- **Remediation:** Migrate to OIDC; delete the secret; rotate the old credential.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SD-B L2 · SSDF: PO.5.1 · CSF 2.0: PR.AA-01

### ASC-DEP-03

**Artifact integrity verified at deployment** · domain `DEP` · activity · owner `appsec-governance` · review every 12 months

The deployment pipeline verifies the provenance attestation of the artifact digest before deploying (or the platform enforces via admission policy).

- **Rationale:** Closes the gap between "built securely" and "what is running".
- **Applies when:** publishes_artifacts
- **Assessment:** automated · evaluator `deploy_verification_executed@1` · min confidence C2 · evidence `deploy.record`
- **How we prove it operates:** deploy-evidence workflow records `gh attestation verify` outcome against the deployed digest.
- **Implementation:** Use security-workflows/deploy-evidence in CD before the deploy step.
- **Remediation:** Add verification step.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SD-A L3 · SSDF: PS.2.1 · Other: SLSA verification

### ASC-DEP-04

**Application runtime secrets held in a managed vault** · domain `DEP` · configuration · owner `appsec-governance` · review every 12 months

Runtime secrets are referenced from Key Vault / AWS Secrets Manager via managed identity, not set as plain app settings or env vars in IaC.

- **Rationale:** Centralised rotation, audit and access control for secrets.
- **Applies when:** has_cloud_scope
- **Assessment:** hybrid · evaluator `scan_clean@1` · min confidence C2 · evidence `scan.iac`, `cloud.posture`
- **Parameters:** `{policy_ids: [secrets-in-app-settings, kv-reference-required]}`
- **How we prove it operates:** IaC policy checks for plaintext secret settings + Defender recommendations on the app's cloud scope.
- **Implementation:** Use Key Vault references / Secrets Manager with managed identity.
- **Remediation:** Move secrets to vault; rotate.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-SD-B L2, I-SD-B L3 · ASVS 5.0: V13 · SSDF: PO.5.1 · CSF 2.0: PR.DS-01

### ASC-TST-01

**DAST executes against a deployed environment** · domain `TST` · activity · owner `appsec-governance` · review every 12 months

A dynamic scan runs against a deployed non-production environment after each release (and at least every 90 days), authenticated for Tier 1/2.

- **Rationale:** Finds runtime issues (headers, session handling, injection reachable at runtime) that SAST cannot.
- **Applies when:** has_web_ui_or_api, deployed
- **Assessment:** automated · evaluator `dast_executed@1` · min confidence C2 · evidence `scan.dast`, `deploy.record`
- **Parameters:** `{authenticated: {'1': true, '2': true, '3': false}, min_urls_crawled: 10}`
- **How we prove it operates:** Attested DAST output naming the target URL, auth context and policy, linked to the release (deploy.record) it tested; a scan that crawled < min_urls is recorded as INCONCLUSIVE, not passing.
- **Implementation:** Call security-workflows/dast (OWASP ZAP baseline/full) post-deploy to test env.
- **Remediation:** Fix findings; fix auth configuration if the scan is inconclusive.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-ST-A L2 · ASVS 5.0: V3, V7, V12, V13 · SSDF: PW.8.2 · CSF 2.0: PR.PS-06

### ASC-TST-02

**API security testing against the API definition** · domain `TST` · activity · owner `appsec-governance` · review every 12 months

APIs with an OpenAPI definition are tested for OWASP API Top 10 classes (authZ/BOLA, mass assignment, rate limiting) using the definition.

- **Rationale:** APIs are the dominant attack surface; generic DAST under-tests them.
- **Applies when:** has_api
- **Assessment:** automated · evaluator `scan_executed@1` · min confidence C2 · evidence `scan.api`
- **How we prove it operates:** Attested API scan evidence bound to the OpenAPI document digest and deployed release.
- **Implementation:** Publish OpenAPI in-repo; call security-workflows/api.
- **Remediation:** Fix findings; add authZ test cases.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-ST-A L2, V-RT-B L2 · ASVS 5.0: V4, V8, V9, V10 · SSDF: PW.8.2 · Other: OWASP API Security Top 10

### ASC-TST-03

**Independent penetration test within period** · domain `TST` · process · owner `appsec-governance` · review every 12 months

Tier 1 apps have a penetration test annually and after major change; Tier 2 biennially; findings imported.

- **Rationale:** Expert testing finds business-logic and chained issues tools miss.
- **Applies when:** deployed
- **Assessment:** manual · evaluator `manual_attestation@1` · min confidence M2 · evidence `assessment.pentest`
- **Parameters:** `{valid_days: {'1': 365, '2': 730}}`
- **How we prove it operates:** Pen-test record (tester org, scope, dates, report SHA-256 in WORM store, findings imported with source=pentest) recorded by AppSec.
- **Implementation:** Book via AppSec; provide test environment and accounts.
- **Remediation:** Remediate findings within SLA; retest.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-ST-B L2 · SSDF: PW.8.2 · CSF 2.0: ID.RA-01

### ASC-TST-04

**Abuse-case tests derived from the threat model** · domain `TST` · activity · owner `appsec-governance` · review every 12 months

High-rated threats from the threat model have corresponding automated negative/abuse-case tests that run in CI.

- **Rationale:** Converts design threats into regression-protected tests.
- **Applies when:** always
- **Assessment:** automated · evaluator `threat_test_linkage@1` · min confidence C2 · evidence `test.security`, `repo.threat_model`
- **Parameters:** `{min_pct_high_threats_tested: 60}`
- **How we prove it operates:** JUnit test properties reference threat IDs from threats.yaml; executed and passing on default branch.
- **Implementation:** Tag tests with a `threat` property (e.g. TM-07); use security-workflows/test-evidence.
- **Remediation:** Add tests for untested high threats.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-RT-B L2, V-RT-A L3 · SSDF: PW.8.2

### ASC-TST-05

**Security regression tests run in CI** · domain `TST` · activity · owner `appsec-governance` · review every 12 months

Automated security tests (authN/authZ, input validation, headers) tagged with ASVS IDs run on every change and pass.

- **Rationale:** Requirements-driven verification that scales.
- **Applies when:** has_source_code
- **Assessment:** automated · evaluator `tests_executed@1` · min confidence C2 · evidence `test.security`
- **Parameters:** `{min_tests: 5}`
- **How we prove it operates:** test-evidence workflow extracts JUnit testcases with asvs properties; pass/fail per requirement.
- **Implementation:** See ASVS implementation guide.
- **Remediation:** Add or fix tests.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: V-RT-A L2, V-RT-A L3 · ASVS 5.0: V6, V7, V8 · SSDF: PW.8.2

### ASC-VUL-01

**Findings are owned and triaged within SLA** · domain `VUL` · outcome · owner `appsec-governance` · review every 12 months

Every open finding maps to an application and owner, and P1–P3 findings are triaged (ticketed, false-positive, or excepted) within the triage SLA.

- **Rationale:** Untriaged findings are invisible risk.
- **Applies when:** always
- **Assessment:** automated · evaluator `triage_within_sla@1` · min confidence C3 · evidence `vuln.posture`
- **Parameters:** `{max_breaches: 0}`
- **How we prove it operates:** Derived from finding state history and the risk model's triage SLA.
- **Implementation:** Champion triages from the platform/Jira queue.
- **Remediation:** Triage overdue findings.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-DM-A L1, I-DM-A L2 · SSDF: RV.2.1 · CSF 2.0: ID.RA-01, ID.RA-06

### ASC-VUL-02

**Vulnerabilities remediated within SLA** · domain `VUL` · outcome · owner `appsec-governance` · review every 12 months

No P1 or P2 finding past remediation SLA; ≥ 90% of P3 within SLA over trailing 90 days. Remediation is verified by re-scan, not by ticket closure.

- **Rationale:** Measures what matters — risk reduction speed — without rewarding low detection.
- **Applies when:** always
- **Assessment:** automated · evaluator `findings_within_sla@1` · min confidence C3 · evidence `vuln.posture`
- **Parameters:** `{max_overdue: {P1: 0, P2: 0}, p3_within_sla_pct: 90}`
- **How we prove it operates:** Finding projection with SLA clock (from risk model version in force at detection); closure requires verification evidence.
- **Implementation:** Prioritise by platform priority; use exceptions when a fix is genuinely blocked.
- **Remediation:** Fix or raise an exception.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-DM-A L2, I-DM-A L3 · SSDF: RV.2.2 · CSF 2.0: ID.RA-06

### ASC-VUL-03

**Exceptions are approved, current and within limits** · domain `VUL` · outcome · owner `appsec-governance` · review every 12 months

All exceptions for the app are approved by the correct approver, within max duration, and not expired; renewals ≤ 2.

- **Rationale:** Exceptions are legitimate risk decisions only if governed.
- **Applies when:** always
- **Assessment:** automated · evaluator `exceptions_governed@1` · min confidence C3 · evidence `vuln.posture`
- **Parameters:** `{max_renewals: 2}`
- **How we prove it operates:** Exception records and their approval audit trail; expiry generates a finding automatically (ADR-021).
- **Implementation:** Use the platform exception workflow; never suppress in tools as a substitute.
- **Remediation:** Remediate, or renew with fresh approval.
- **Exceptions:** not permitted
- **Mappings:** SAMM: G-PC-B L2, I-DM-A L2 · CSF 2.0: ID.RA-07, GV.RM-04

### ASC-VUL-04

**Recurring weakness classes are analysed** · domain `VUL` · process · owner `appsec-governance` · review every 12 months

Quarterly, the team reviews its top recurring CWE classes (computed by the platform) and records a root-cause action.

- **Rationale:** Moves from fixing instances to eliminating classes.
- **Applies when:** always
- **Assessment:** hybrid · evaluator `periodic_process@1` · min confidence M1 · evidence `process.review_record`
- **How we prove it operates:** Platform pre-generates the recurring-CWE report; the review record (attendees, decisions, linked tickets) is submitted within 120 days of the last.
- **Implementation:** Run in the team's retrospective with the champion.
- **Remediation:** Hold the review.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: I-DM-B L2, I-DM-B L3 · SSDF: RV.3.1, RV.3.2, RV.3.3 · CSF 2.0: ID.IM-02

### ASC-OPS-01

**Security-relevant application logs reach the SIEM** · domain `OPS` · activity · owner `appsec-governance` · review every 12 months

Authentication, authorisation failures, admin actions and security exceptions are logged and delivered to Sentinel (or Exabeam) with the application identifier; the log source is healthy.

- **Rationale:** Detection and incident response depend on it.
- **Applies when:** deployed
- **Assessment:** automated · evaluator `log_source_healthy@1` · min confidence C3 · evidence `siem.log_source_health`
- **Parameters:** `{required_event_categories: [authentication], window_hours: 24}`
- **How we prove it operates:** Scheduled KQL query via the Log Analytics query API returns events for the app's tag in the window. Reader role created by `modules/sentinel`; the app tagging convention is a project task.
- **Implementation:** Use the logging standard; tag logs with the application ID.
- **Remediation:** Restore the log pipeline.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-IM-A L1, O-IM-A L2 · ASVS 5.0: V16 · CSF 2.0: PR.PS-04, DE.CM-09

### ASC-OPS-02

**Incident response readiness for the application** · domain `OPS` · process · owner `appsec-governance` · review every 12 months

An app-specific incident runbook (contacts, kill switches, credential rotation steps, data-breach decision points) exists and has been exercised or reviewed in 12 months.

- **Rationale:** Reduces time to contain.
- **Applies when:** deployed
- **Assessment:** manual · evaluator `manual_attestation@1` · min confidence T1:M2 / T2:M1 · evidence `assessment.manual_control`
- **How we prove it operates:** Runbook link (version-controlled) + exercise record reviewed by SOC/AppSec.
- **Implementation:** Template in docs/runbooks.
- **Remediation:** Write/exercise the runbook.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-IM-B L1, O-IM-B L2 · CSF 2.0: RS.MA-01

### ASC-OPS-03

**Cloud posture findings on the application's scopes are within SLA** · domain `OPS` · outcome · owner `cloud-security` · review every 12 months

High/critical Defender for Cloud / Security Hub findings on subscriptions, resource groups or accounts mapped to the app are remediated within SLA.

- **Rationale:** Runtime configuration drift is invisible to repo scanning.
- **Applies when:** has_cloud_scope
- **Assessment:** automated · evaluator `findings_within_sla@1` · min confidence C3 · evidence `cloud.posture`
- **Parameters:** `{source: [defender, security_hub]}`
- **How we prove it operates:** Connector pulls findings scoped by the app's cloud mapping (subscription/RG/tag/account); risk engine assigns SLA.
- **Implementation:** Map cloud scopes in application.yaml; tag resources with app ID.
- **Remediation:** Fix configuration; or except with compensating control.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-EM-A L2, O-EM-A L3 · CSF 2.0: PR.PS-01, ID.RA-01

### ASC-OPS-04

**Deployed images and runtimes are patched regularly** · domain `OPS` · outcome · owner `appsec-governance` · review every 12 months

Every deployed image digest was built within the last 30 days (Tier 1/2) or 90 days (Tier 3), or has no fixable high/critical OS-package vulnerabilities.

- **Rationale:** Base-image patches only reach production if images are rebuilt and redeployed.
- **Applies when:** builds_or_deploys_containers, deployed
- **Assessment:** automated · evaluator `image_patch_age@1` · min confidence C2 · evidence `deploy.record`, `scan.container`
- **Parameters:** `{max_age_days: {'1': 30, '2': 30, '3': 90}}`
- **How we prove it operates:** deploy.record digests joined to build timestamp (provenance) and container scan results.
- **Implementation:** Scheduled rebuilds; Renovate/Dependabot for base images.
- **Remediation:** Rebuild and redeploy.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-EM-B L1, O-EM-B L2 · CSF 2.0: PR.PS-02

### ASC-OPS-05

**Data stores are inventoried, encrypted and backed up per classification** · domain `OPS` · configuration · owner `appsec-governance` · review every 12 months

Data stores listed in application.yaml match discovered cloud data resources; encryption and backup settings meet the classification baseline.

- **Rationale:** SAMM Data Protection; prevents shadow data stores.
- **Applies when:** has_cloud_scope
- **Assessment:** hybrid · evaluator `data_store_baseline@1` · min confidence C1 · evidence `cloud.posture`, `registry.application`
- **How we prove it operates:** Azure Resource Graph / AWS Config resource inventory for mapped scopes compared to declared stores; encryption/backup properties checked.
- **Implementation:** Declare data stores in application.yaml.
- **Remediation:** Declare or remove undeclared stores; enable backups.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-OM-A L1, O-OM-A L2 · ASVS 5.0: V14 · CSF 2.0: ID.AM-07, PR.DS-01
- **Notes:** PROPOSED for Phase 8+; depends on reliable cloud-scope mapping.

### ASC-OPS-06

**Retired applications are fully decommissioned** · domain `OPS` · outcome · owner `appsec-governance` · review every 12 months

Applications with lifecycle_status=retired have repos archived, cloud scopes empty or deleted, secrets revoked, and DNS removed within 90 days.

- **Rationale:** Abandoned assets are a common breach entry point (dangling DNS, forgotten credentials).
- **Applies when:** lifecycle_retired
- **Assessment:** automated · evaluator `decommission_complete@1` · min confidence C1 · evidence `repo.access`, `cloud.posture`
- **Parameters:** `{within_days: 90}`
- **How we prove it operates:** Repo archived flag; no resources in mapped scopes; no active secrets in mapped vaults.
- **Implementation:** Follow the decommissioning runbook.
- **Remediation:** Complete outstanding decommission steps.
- **Exceptions:** allowed, max days T1:90 / T2:180 / T3:365 / T4:365
- **Mappings:** SAMM: O-OM-B L1, O-OM-B L2 · CSF 2.0: ID.AM-08

