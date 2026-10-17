# Security model: what the platform proves, and how strongly

## Evidence, not configuration

Every control state rests on evidence records. Each record says what was observed, by whom, about which commit or
artifact, when, and how strongly that can be trusted:

| Confidence | Meaning | Example |
|---|---|---|
| C0 | Declared: a claim only. Never satisfies a control | "We use CodeQL" in a document |
| C1 | Configured: read from the system of record's API | Branch protection requires 2 reviews |
| C2 | Executed: an approved pipeline ran on this exact commit | The approved SAST workflow at an approved SHA produced these results |
| C3 | Attested: executed and signed by the approved workflow's identity, or executed by the system of record | GitHub artifact attestation verified; GitHub secret scanning alerts |
| M1 | Manual, recorded by the owning team | Self-assessed SAMM answers |
| M2 | Manual, reviewed by someone independent of the owning team | Pen test approved by AppSec |

A control says which confidence it needs. Automated and manual evidence are different kinds: an M2 review never
satisfies a control that needs a C2 scan, and the reverse.

## Why a team cannot fake a scan

The platform pulls evidence; nobody pushes it. For each evidence bundle it checks, against GitHub's or GitLab's API:

1. the pipeline that produced it is an **approved** one at an **approved commit** (GitHub: `referenced_workflows`;
   GitLab: the merged job equals the approved component, [ADR-033](../../adr/ADR-033-gitlab-evidence-trust.md));
2. the manifest describes **this** repository, commit and run;
3. every file matches its SHA-256;
4. where available, the signature names the approved workflow (C3).

Anything else is rejected with a reason code, recorded and visible. Accepted evidence is stored write-once and chained
by hash; the chain head is exported daily, so later tampering is detectable.

## Limits we state rather than hide

- **Private GitHub repositories without Enterprise Cloud: C2 at most** (no attestation storage).
- **GitLab: C2 at most** (CI/CD variables can influence jobs; no component-scoped signature).
- **Self-hosted, non-ephemeral runners: C2 at most** (a previous job could poison the runner).
- Manual evidence is only as good as the reviewer; M2 means independent, not infallible.
- Compliance is not legal compliance: the platform shows evidence for controls you defined.
