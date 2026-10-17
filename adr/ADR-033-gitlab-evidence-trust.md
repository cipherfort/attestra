# ADR-033: GitLab evidence trust: verify the merged job against the approved component; cap at C2

**Status:** Accepted (2026-10-16), from the M3 spike · **Related:** [ADR-005](ADR-005-github-primary-source-integration.md), [ADR-016](ADR-016-evidence-immutability.md), [ADR-032](ADR-032-open-source-product.md), [evidence model](../docs/architecture/04-evidence-model.md)

## Context

On GitHub the platform proves which code produced evidence in two independent ways. GitHub reports the reusable
workflows a run called, pinned to a commit (`referenced_workflows`). The Sigstore signature names that same reusable
workflow. Approving the workflow's commit therefore approves everything that ran.

GitLab has neither. A GitLab CI/CD component is text that the project's own pipeline includes: the jobs run as the
project's jobs, and a GitLab keyless signature names the project's `.gitlab-ci.yml`, not the component. ADR-032 made
GitLab a 1.0 platform on condition that a spike first established what can be proven.

## The spike (GitLab CE 19.5, deploy/local/gitlab.compose.yaml)

A group, a `security-components` project with one component, an application project including it **pinned to a
commit SHA**, an instance runner, and a group access token with only `read_api` + `read_repository` at Reporter level
(what the platform holds). Findings:

| Question | Result |
|---|---|
| Can a read-only token see the CI configuration that applies at the job's commit? | **Yes**: `GET /projects/:id/ci/lint?content_ref=<sha>&include_jobs=true` returns every include (a component's location with its pinned SHA) and the fully merged YAML |
| Does including the approved component prove the job is the component's? | **No**: the project overrode `script:` of the included job (and injected a `default: before_script`). The include list still showed only the approved component; **the merged job definition showed the forged script** |
| Can the platform render the component's expected job itself? | Not through GitLab (`POST /ci/lint` with content is 403 for Reporter). **Yes from the source**: the component file at the approved SHA is readable (`read_repository`) |
| Job metadata and artifacts? | Yes: jobs API (name, status, commit, pipeline) and `GET /jobs/:id/artifacts` |
| CI/CD variable names (static cloud credentials check)? | **No**: 403 below Maintainer. Project variables also reach the job's environment, so a maintainer can influence a component job (e.g. `PATH`, `PYTHONPATH`) without changing its YAML |
| MR approval rules, push rules, protected environments? | 404 on GitLab Free/CE (Premium features). Protected branches and members are readable |

## Decision

1. **Evidence is accepted from a GitLab job only when its merged definition equals the approved component's.**
   For the job named in the manifest, at the job's commit:
   - every include is either local to the same commit or pinned to a 40-character SHA (no branch, tag or
     remote URL includes: they can change after the fact);
   - the component named in `config/trusted-producers.yaml` (`gitlab:` section) is included at an approved SHA;
   - the merged job equals the job rendered from the component file at that SHA (inputs at their defaults) for every
     key except `stage`, `tags`, `needs`, `rules` and `when` (these only decide whether, when and where it runs);
   - the job sets `inherit: {default: false, variables: false}` so project-level `default:` and global `variables:`
     do not reach it.

   Any difference → `UNAPPROVED_WORKFLOW_REF` with the differing keys in the rejection detail.
2. **GitLab evidence is capped at C2.** Two limits keep it below C3:
   - project CI/CD variables reach the job environment and the platform cannot see them;
   - no signature names the component.

   The shipped components run the evidence tool with a scrubbed environment (`env -i`, absolute interpreter path,
   `python3 -I`), which narrows the first limit but does not remove it.
3. **No attestation step for GitLab at 1.0.** Keyless signing on GitLab proves the project pipeline signed, which the
   platform already knows from the API. Revisit if GitLab exposes component provenance (a signing identity or an API
   field naming the component and its SHA).
4. **Settings evidence on GitLab separates "absent" from "unreadable".** A feature the GitLab tier does not have
   is a fact about the project and is reported as absent, with the reason in the summary (`unavailable_on_tier`). For
   example, on GitLab Free merge requests cannot require approvals, so the branch rules report zero required
   approvals and the review control is not satisfied, which is true. Something the platform's token cannot read is
   a gap and is never guessed: CI/CD variable names need Maintainer, so `repo.environments` is not produced and the
   controls that need it show NO_EVIDENCE. Settings with no GitLab equivalent (GitHub Actions permissions) are gaps
   too.

## Consequences

- GitLab users get the same controls and workflow as GitHub users, with evidence at most C2. Controls that require
  C3 (none at 1.0 for scan evidence) cannot be satisfied from GitLab. The UI shows the cap, as it does for private
  GitHub repositories without Enterprise Cloud.
- Verification needs the job's commit to remain lintable. A deleted component project, or an include that no
  longer resolves, rejects evidence that has not been ingested yet. That is fail-closed, and ingestion runs on the
  job webhook, minutes after the job.
- The platform's GitLab token stays read-only (Reporter, `read_api`, `read_repository`).

## Alternatives considered

| Option | Why not |
|---|---|
| Trust the include list | The spike forged a result while the include list stayed clean |
| Pin a scanner image digest and check the job's image | The job's `script:` is still the project's to override; the image alone proves nothing about what ran |
| Keyless signing with the GitLab id token | The certificate names the project's `.gitlab-ci.yml`, not the component |
| C3 for GitLab | Not provable today (see decision 2) |
