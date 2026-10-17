# Secure Software Development Lifecycle (SSDLC) Standard

| | |
|---|---|
| ID | STD-01 · Status: DRAFT, REQUIRES HUMAN APPROVAL (Governance Board) |
| Owner | Head of Application Security |
| Applies to | All applications built or maintained by the organisation (in-house or by suppliers in our repositories) |
| Review | Annually, and on a major catalogue version |
| Frameworks | NIST SSDF (SP 800-218 v1.1), OWASP SAMM 2.0 |

## 1. Purpose

Defines the security activities each application must perform at each lifecycle stage, scaled by tier. This is the umbrella standard. Detailed standards (listed in section 5) define each activity. The [control catalogue](control-catalogue.md) defines how each one is tested and evidenced.

## 2. Principles

1. **Risk-proportionate:** requirements scale with the application's tier ([Classification Standard](application-classification-standard.md)).
2. **Paved road first:** use the organisation's reusable security workflows and templates. Deviations need an exception.
3. **Evidence, not assertion:** an activity counts only when the platform has evidence of it at the required confidence ([Evidence Management Standard](evidence-management-standard.md)).
4. **Fix by verification:** a security defect is closed only when a re-test proves the fix.

## 3. Lifecycle requirements

| ID | Stage | Requirement ("shall") | T1 | T2 | T3 | T4 | Proven by |
|---|---|---|---|---|---|---|---|
| SDLC-01 | Initiate | Register the application with business and technical owners | ● | ● | ● | ● | ASC-GOV-01 |
| SDLC-02 | Initiate | Classify the application and keep the classification current | ● | ● | ● | ● | ASC-GOV-02 |
| SDLC-03 | Initiate | Assign a trained security champion to the owning team | ● | ● | ○ | – | ASC-GOV-03 |
| SDLC-04 | Requirements | Define the ASVS target level and capability profile | ● | ● | ● | ○ | ASC-REQ-01 |
| SDLC-05 | Requirements | Record supplier/third-party security requirements | ● | ○ | – | – | ASC-REQ-03 (manual) |
| SDLC-06 | Design | Produce and review a threat model. Keep it current. | ● | ● | ○ | – | ASC-TM-01/02/03 |
| SDLC-07 | Design | Obtain an architecture security review before first production release and on material change | ● | ● | ○ | – | ASC-ARC-01 (manual) |
| SDLC-08 | Design | Use supported runtimes and frameworks (no end-of-life components) | ● | ● | ● | ○ | ASC-ARC-02 |
| SDLC-09 | Implement | Protect the default branch (review, required checks, no force-push) | ● | ● | ● | ○ | ASC-SRC-01/02 |
| SDLC-10 | Implement | Keep secrets out of source. Enable secret scanning with push protection. | ● | ● | ● | ● | ASC-SRC-03/04 |
| SDLC-11 | Build | Run SAST, SCA, IaC and container scanning via the paved-road pipeline | ● | ● | ● | ○ | ASC-BLD-01/02/04/05 |
| SDLC-12 | Build | Generate SBOMs for release artifacts | ● | ● | ● | ○ | ASC-BLD-03 |
| SDLC-13 | Build | Attest build provenance for release artifacts | ● | ● | ○ | – | ASC-BLD-06 |
| SDLC-14 | Build | Block new vulnerable, malicious or licence-denied dependencies | ● | ● | ○ | – | ASC-BLD-07/08/09 |
| SDLC-15 | Verify | Run security regression tests mapped to ASVS | ● | ● | ○ | – | ASC-TST-05, ASC-REQ-02 |
| SDLC-16 | Verify | Run DAST / API security tests against deployed non-production environments | ● | ● | ○ | – | ASC-TST-01/02 |
| SDLC-17 | Verify | Commission independent penetration tests | ● (annual) | ● (biennial) | ○ | – | ASC-TST-03 (manual) |
| SDLC-18 | Deploy | Deploy only via protected pipeline environments, using OIDC (no static cloud credentials) | ● | ● | ● | ○ | ASC-DEP-01/02 |
| SDLC-19 | Deploy | Verify artifact integrity at deployment | ● | ○ | – | – | ASC-DEP-03 |
| SDLC-20 | Operate | Remediate vulnerabilities within SLA | ● | ● | ● | ● | ASC-VUL-01/02 |
| SDLC-21 | Operate | Send security-relevant logs to the SIEM | ● | ● | ○ | – | ASC-OPS-01 |
| SDLC-22 | Operate | Keep an application incident runbook | ● | ○ | – | – | ASC-OPS-02 (manual) |
| SDLC-23 | Operate | Remediate cloud posture findings within SLA. Rebuild images regularly. | ● | ● | ○ | – | ASC-OPS-03/04 |
| SDLC-24 | Retire | Fully decommission retired applications within 90 days | ● | ● | ● | ● | ASC-OPS-06 |

● mandatory · ○ recommended · – not applicable. The authoritative tier applicability is the catalogue. Where this table differs, the catalogue wins and this table is corrected.

## 4. Roles

Technical owner: accountable for meeting this standard. Security champion: drives activities within the team. AppSec: facilitates threat models and reviews, and maintains the paved road. Business Unit Security Lead: accountable for business unit compliance. See the [RACI](../../adoption-kit/programme/raci/raci.md).

## 5. Related standards

[Application Classification](application-classification-standard.md) · [Security Requirements](security-requirements-standard.md) · [Threat Modelling](threat-modelling-standard.md) · [Secure Architecture](secure-architecture-standard.md) · [Security Testing](security-testing-standard.md) · [Vulnerability Management](vulnerability-management-standard.md) · [SBOM](sbom-standard.md) · [Software Supply Chain Security](software-supply-chain-security-standard.md) · [Security Exceptions](security-exception-standard.md) · [Evidence Management](evidence-management-standard.md) · [GitHub Security Baseline](github-security-baseline.md) · [Pipeline Security](pipeline-security-standard.md) · [Open Source Policy](open-source-policy.md)

## 6. Exceptions

Via the [Security Exception Standard](security-exception-standard.md) only.

## 7. SSDF alignment

| SSDF group | Covered by |
|---|---|
| PO (Prepare the Organisation) | SDLC-01–05, governance model, champions, toolchain (paved road) |
| PS (Protect the Software) | SDLC-09, 10, 12, 13, 19 |
| PW (Produce Well-Secured Software) | SDLC-04, 06–08, 11, 14–17 |
| RV (Respond to Vulnerabilities) | SDLC-20, Vulnerability Management Standard, SECURITY.md (ASC-GOV-05) |
