# Security policy

This project verifies other people's security evidence, so we hold our own code to the same standard. Thank you for helping.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). If you cannot use GitHub, email [info@cipherfortsecurity.com](mailto:info@cipherfortsecurity.com) with "SECURITY" in the subject.

Include what you can of:
- the affected component (api, hook, worker, ui, a plugin, a pipeline, the Helm chart);
- version or commit;
- steps to reproduce;
- impact;
- any suggested fix.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| First assessment (valid? severity?) | 10 working days |
| Fix or mitigation for critical and high issues | 30 days |
| Public disclosure | When a fix is released, or at 90 days, whichever is first, coordinated with you |

We credit reporters in the advisory unless you prefer otherwise. We do not run a paid bug bounty.

## Supported versions

Before 1.0, only the latest release gets security fixes. From 1.0, the latest minor release and the previous one do.

## Scope

**In scope:**
- this repository's code and container images;
- the Helm chart;
- the shipped pipelines and the `aap-evidence` tool;
- evidence verification;
- authentication and authorization;
- the tenant data boundary (row-level security).

**Especially welcome:** any way to make the platform accept evidence it should reject (forged, replayed, tampered or mis-bound), or to escalate a role.

**Out of scope:**
- vulnerabilities in third-party systems the platform connects to (GitHub, GitLab, Jira, Dependency-Track, DefectDojo, cloud providers): report those to their owners;
- findings that need a compromised administrator account, unless they bypass a stated control.
