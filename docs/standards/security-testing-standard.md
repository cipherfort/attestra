# Security Testing Standard

| | |
|---|---|
| ID | STD-06 · Status: Template. Adapt it and have it approved in your organization. |
| Owner | AppSec lead |
| Related | [Pipeline architecture](../architecture/05-pipeline-architecture.md), [Pipeline Security Standard](pipeline-security-standard.md) |

## 1. Purpose

Defines the automated and manual security testing each application must undergo, by tier, and what counts as a valid test.

## 2. Test types and frequency

| Test | Tier 1 | Tier 2 | Tier 3 | Tier 4 | Default tool | Control |
|---|---|---|---|---|---|---|
| SAST | Every change, security-extended suite | Every change, security-extended | Every change, default suite | Recommended | CodeQL | ASC-BLD-01 |
| SCA + malicious packages | Every dependency change + weekly | same | same | same | OSV-Scanner, Dependabot | ASC-BLD-02/09 |
| Dependency review gate | Every PR | Every PR | Recommended | – | dependency-review-action | ASC-BLD-07 |
| Secret detection | Continuous + push protection | same | same | same | GHAS secret scanning | ASC-SRC-03/04 |
| IaC scan | Every IaC change | same | same | Recommended | Checkov, Trivy config | ASC-BLD-04 |
| Container scan | Every image build + weekly on deployed digests | same | same | Recommended | Trivy | ASC-BLD-05 |
| Workflow hardening scan | Every workflow change | same | same | Recommended | zizmor, actionlint | ASC-SRC-06 |
| Security regression tests (ASVS-tagged) | Every change | Every change | Recommended | – | Team frameworks | ASC-TST-05 |
| Abuse-case tests from threat model | Every change, ≥ 60% of high threats | Recommended | – | – | Team frameworks | ASC-TST-04 |
| DAST | Authenticated, each release + ≤ 90 days | Authenticated, each release + ≤ 90 days | Baseline, recommended | – | OWASP ZAP | ASC-TST-01 |
| API security testing | Each release | Each release | Recommended | – | ZAP API scan, Schemathesis | ASC-TST-02 |
| Penetration test | Annual + major change | Biennial + major change | Risk-based | – | Independent tester | ASC-TST-03 |

## 3. Validity rules

| ID | Rule |
|---|---|
| TST-01 | Only tests run by the approved reusable workflows (or the authoritative GHAS APIs) produce automated evidence. Ad-hoc local scans do not. |
| TST-02 | Evidence must be bound to the default-branch commit or deployed artifact digest it tested |
| TST-03 | SAST must cover **all** languages detected in the repository. Partial coverage gives PARTIAL state. |
| TST-04 | DAST must record target URL, environment, authentication mode and URLs crawled. A scan below the crawl threshold is INCONCLUSIVE. |
| TST-05 | DAST/API tests run only against non-production environments, unless a production test is approved by the service owner and the SOC is notified |
| TST-06 | Pen-test reports are stored in WORM evidence storage. Findings are imported into the platform with `source=pentest`. Retests are recorded. |
| TST-07 | Tests on public repositories must not publish finding detail in logs, PR comments or job summaries |
| TST-08 | A failing security test counts as "control operating, outcome failing". It is never suppressed to make a pipeline pass. Use an exception. |

## 4. Gating

Gates are introduced per tier, after observe periods, by Governance Board decision ([gating roadmap](../architecture/05-pipeline-architecture.md#9-gating-roadmap-observe--gate)). Gates are GitHub-native required checks. Bypass is via audited ruleset bypass lists only.

## 5. Penetration test requirements

Scope agreed with AppSec. Tester independence (an external CREST-accredited provider or the internal red team; the accreditation requirement is optional). Authenticated testing across all roles. Business-logic testing. Report with CVSS and reproduction steps. Retest of fixed findings within 90 days.
