# Business case — {{ORGANIZATION}}

## Problem and cost of doing nothing

{{e.g. audit findings, incidents, time spent assembling evidence by hand ({{HOURS}} per audit), unknown exposure to
the next widely exploited vulnerability}}

## Options

| Option | Cost (year 1 / year 2+) | Gives |
|---|---|---|
| Do nothing | {{£/$}} (manual evidence, audit effort) | Status quo |
| A commercial ASPM product | {{£/$}} licences + integration | {{…}} |
| This platform (open source) | Infrastructure {{£/$}} + {{N}} FTE to run and onboard | Evidence-based assurance you control; rules as code |

## Costs of this option

- Infrastructure: Kubernetes namespace, PostgreSQL, a write-once bucket: {{£/$ per month}} (see the Helm and
  Terraform examples).
- People: platform owner {{FTE}}; AppSec time for approvals and reviews {{FTE}}; champions {{TIME_ALLOCATION}}.
- Scanners: the shipped pipelines use open-source tools; CodeQL on private GitHub repositories needs GitHub Code
  Security ({{£/$}}), or use the Semgrep-based GitLab components.

## Benefits

| Benefit | Measure | Expected |
|---|---|---|
| Faster audits | Hours to evidence a control | {{from}} → {{to}} |
| Faster response to new critical vulnerabilities | Time to answer "are we affected?" | {{days}} → minutes |
| Risk reduction | P1 open past SLA | {{N}} → 0 |
