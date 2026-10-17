# Independent security review: scope and brief

Status: PREPARED. REQUIRES HUMAN APPROVAL and an external reviewer: the maintainer commissions the review (pen test and
design review) before 1.0. Findings are fixed or published as known issues before the release.

## What the product protects

A map of every application's exploitable weaknesses and the evidence behind each security claim. The two properties
that matter most:
1. **Evidence integrity:** no one can make a control look satisfied without the approved pipeline having run on that
   commit (or an independent person having assessed it), and no one can silently change or delete evidence.
2. **Confidentiality by scope:** a person sees only the applications of the units they belong to.

## In scope

| Area | Entry points | Start from |
|---|---|---|
| Evidence ingestion | GitHub workflow artifacts and attestations; GitLab job artifacts and CI configuration | `backend/src/aap/ingest/`, `domain/evidence.py`, `connectors/gitlab.py`, [ADR-033](../../adr/ADR-033-gitlab-evidence-trust.md) |
| Shipped pipelines | `pipelines/aap_evidence.py`, `pipelines/github/`, `pipelines/gitlab/` | [pipelines/README.md](../../pipelines/README.md) |
| Web application and API | Browser (OIDC BFF, CSRF), bearer tokens, every `/api/v1` operation | `api/`, [schemas/api/openapi.yaml](../../schemas/api/openapi.yaml), [access-control model](access-control-model.md) |
| Webhook receiver | `/github/webhook`, `/gitlab/webhook` (the only internet-facing process) | `hook/app.py` |
| Database | Row-level security, role separation, ledgers and hash chains | `schemas/database/0001_core.sql`, `migrations/`, `tests/database/` |
| Write-capable integrations | Jira, GitHub/GitLab Issues, chat webhooks, SIEM sinks | `connectors/`, `services/ticketing.py` |
| Deployment | Helm chart, container image, Compose stack | `charts/attestra/`, `Dockerfile`, `deploy/compose/` |

Out of scope: the adopter's own identity provider, cloud accounts and scanners; findings in demo data.

## Suggested tests

- Forge evidence: a workflow or GitLab job that is not the approved one; an approved one at another commit; a
  manifest describing another repository or run; tampered files; replayed artifacts.
- Cross-scope reads through every endpoint (IDOR), including exports, the CVE impact query and assessment/exception ids.
- Segregation of duties: approve your own exception, classification, false positive or assessment; grant yourself a role.
- Webhook spoofing and replay; request smuggling to the hook; oversized and malformed archives and documents.
- Session handling (fixation, CSRF, logout, idle and absolute timeouts), OIDC (issuer, nonce, PKCE, back-channel URL).
- Container and Kubernetes hardening: escape to the node, metadata service, secrets of other processes.

## What we provide the reviewer

A deployment from the Helm chart on a throwaway cluster with the demo world; accounts for every role; the threat model
([platform security architecture](platform-security-architecture.md), section 4.1 for the current surface); the test
suites, including the fuzzers and the live GitLab forgery test.
