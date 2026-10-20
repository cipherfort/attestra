# ASVS Implementation Guide (for engineering teams)

| | |
|---|---|
| Audience | Engineers and security champions |
| Status | Guidance for application teams |
| Standard | [Security Requirements Standard](../standards/security-requirements-standard.md) |

## 1. In one paragraph

Declare what your app does in `.security/asvs.yaml`. The platform works out which ASVS 5.0 requirements apply. Requirements become **verified** when evidence proves them: a passing test tagged with the requirement ID, a configuration check, or an independent review. Scanner silence alone never counts. Your app page shows each requirement's status and which evidence backs it.

## 2. Step 1: declare your profile

Copy [`templates/repo-contract/.security/asvs.yaml`](../../templates/repo-contract/.security/asvs.yaml) and set:

| Field | Set it to | Effect |
|---|---|---|
| `target_level` | At least your tier's target (T1 → 3, T2 → 2, T3/T4 → 1) | ASC-REQ-01 checks this |
| `capabilities.web_frontend` | true if you serve browser UI | Scopes V3 |
| `capabilities.api` | true if you expose an API | Scopes V4 |
| `capabilities.file_handling` | true if you accept or serve files | Scopes V5 |
| `capabilities.authentication` | `federated` (the workforce or customer identity provider), `local`, `mixed`, `none` | Scopes V6/V8 sections |
| `capabilities.sessions`, `self_contained_tokens`, `oauth_oidc`, `webrtc` | As applicable | V7, V9, V10, V17 |

If you think a requirement genuinely doesn't apply, add it to `not_applicable` with a justification. The platform records these requests but has no approval step for them yet, so until one exists the requirement still counts as applicable (an exception is the approved route today).

## 3. Step 2: tag your security tests

Add the ASVS requirement ID as a JUnit property. The `test-evidence` workflow collects these on every default-branch run.

**JUnit XML (any framework that emits it):**
```xml
<testcase classname="ClaimAuthorizationTest" name="otherCustomerClaimReturns404">
  <properties>
    <property name="asvs" value="V8.2.2"/>   <!-- several: "V8.2.1,V8.2.2" -->
    <property name="threat" value="TM-01"/>
  </properties>
</testcase>
```

**pytest** (`record_property` writes JUnit properties):
```python
def test_other_customer_claim_returns_404(client, record_property):
    record_property("asvs", "V8.2.2")   # several: "V8.2.1,V8.2.2"
    record_property("threat", "TM-01")
    assert client.get("/claims/other-customer-id").status_code == 404
```

**JUnit 5 / Java**: emit the properties with your reporter (for example Gradle/Maven Surefire `<properties>` per test via a `TestExecutionListener`). **Jest**: `jest-junit` with a `testCasePropertiesFile` that maps your test names to `asvs` / `threat` properties. Only the JUnit XML matters: the platform reads the `asvs` and `threat` properties (`backend/src/aap/ingest/parsers.py`, `parse_junit`).

> Use the official ASVS 5.0 requirement IDs (`V<chapter>.<section>.<requirement>`), as listed in `catalogue/frameworks/asvs-5.0.0-requirements.yaml` (imported from the official release by `tools/catalogue/import_asvs.py`). Do not copy them from older ASVS versions: IDs changed in 5.0. A requirement counts as verified when a linked test passed and none failed; a requirement outside your target level or your applicable chapters does not count towards coverage.

## 4. Step 3: what else verifies requirements

| Method | How | Example chapters |
|---|---|---|
| Configuration check | DAST checks headers/TLS/cookies; IaC policies check platform config | V3, V12, V13 |
| Manual review | AppSec review or pen test lists the requirement IDs it covered (time-bound) | V2 business logic, V11 |
| Scanner (supporting only) | CodeQL/ZAP with no relevant findings → `scanned_no_issues`; a finding mapped by CWE → `failed` | V1, V15 |

## 5. Targets

Tier 1/2: ≥ 80% of applicable requirements VERIFIED (ASC-REQ-02). Prioritise using your threat model: requirements that mitigate high threats first.

## 6. FAQ

- **We use a framework that handles X. Is that verified?** Only if a test or configuration check proves it in *your* app. Framework defaults can be disabled.
- **Can AppSec mark requirements verified for us?** Only by recording a review, which is time-bound evidence like anything else.
- **What about ASVS 4.0.3 mappings in our existing tests?** Re-map to 5.0 IDs. AppSec can provide a mapping assist.
