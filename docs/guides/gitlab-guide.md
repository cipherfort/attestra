# Using the platform with GitLab

Status: IMPLEMENTED and tested end to end against GitLab CE 19.5 with a real runner (`backend/tests/integration/test_gitlab_live.py`,
nightly in CI). Evidence from GitLab is capped at **C2**; [ADR-033](../../adr/ADR-033-gitlab-evidence-trust.md) explains why.

## What the platform does on GitLab

| | GitLab |
|---|---|
| Settings evidence | Protected default branch, merge request approvals (Premium), "pipelines must succeed", CODEOWNERS (sections supported), project members, visibility, secret push protection (Ultimate) |
| Scan evidence | The shipped CI/CD components (`pipelines/gitlab/`): Semgrep, OSV-Scanner, gitleaks, Checkov, Syft |
| Proof that the approved component ran | The job's commit is linted with a read-only token. Every include must be pinned to a commit SHA, and the merged job must equal the component file at an approved SHA (only scheduling keys such as `stage` may differ) |
| Tickets | GitLab Issues (optional), or Jira |
| Delivery | Group webhook for job and push events (Premium); otherwise the platform polls finished component jobs on its schedule |

## Set up (once per organization)

You need a GitLab group and a group Owner's personal access token (scope `api`) for the set-up only. It is not stored.

```bash
cd backend
# 1. The platform's read-only token (Reporter; read_api + read_repository), and the webhook on Premium
GITLAB_ADMIN_TOKEN=... uv run aap bootstrap gitlab --url https://gitlab.example.org --group example-org \
  --admin-token-env GITLAB_ADMIN_TOKEN --public-url https://aap-hooks.example.org   # add --with-issues for GitLab Issues
# 2. Create <group>/security-components and render the components into it; merge through review
uv run aap pipelines export --provider gitlab --to ../../security-components
# 3. Approve the merged commit (edits config/trusted-producers.yaml → gitlab:; merge that through review)
uv run aap pipelines approve --provider gitlab --repository example-org/security-components --sha <commit> --release v1.0.0
# 4. The include each application project adds to its .gitlab-ci.yml
uv run aap pipelines caller --provider gitlab --host gitlab.example.org --repository example-org/security-components \
  --sha <commit> --release v1.0.0
```

Settings for the deployment: `AAP_GITLAB_URL`, `AAP_GITLAB_GROUP` (or `plugins.gitlab` in `aap.yaml`).

## Rules for application projects

- Include the components exactly as `aap pipelines caller` prints them, pinned to the approved SHA.
- **Do not override the included jobs** (`aap-sast`, `aap-sca`, ...) in your `.gitlab-ci.yml`. A job that differs from
  the approved component is rejected (`UNAPPROVED_WORKFLOW_REF`) and the rejection names the changed keys. You may
  change `stage` (an input), and `tags`, `rules`, `needs` and `when`.
- Includes from branches, tags or URLs make every job's evidence unverifiable: pin them to commit SHAs.
- Register the application from the platform's **Register an application** page (Source control: GitLab), or
  `aap apps register --provider gitlab group/project`.

## Known limits

- **C2 at most.** Project CI/CD variables reach the job environment and the platform's Reporter token cannot see them;
  no GitLab signature names the component. The components run the evidence tool with a scrubbed environment, which
  narrows but does not remove the first limit.
- **GitLab Free.** Merge request approvals cannot be required, so the review control is not satisfied (that is the
  true state). Protected environments and CI/CD variable names are not readable, so `repo.environments` is a gap.
- **Container scanning.** No GitLab component yet: it needs the image digest as an input, and inputs other than
  `stage` would break the "equals the approved component" check. Scan images from a GitHub workflow or add the
  evidence manually until a design for verified inputs lands.
- **Semgrep rules** come from the Semgrep registry at run time (`p/default`). Vendor them into
  `security-components` to pin them.

## Try it locally

`deploy/local/gitlab.sh` starts GitLab CE and a runner, creates the group, runs `aap bootstrap gitlab`, registers a
runner and prints the command for the live end-to-end test (~4 GB RAM, first start several minutes).
