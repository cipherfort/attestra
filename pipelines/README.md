# Shipped security pipelines

The scans that produce the platform's automated evidence. You run them in **your own** `security-workflows`
repository, so you control and approve exactly which code is trusted to produce evidence.

| Workflow | Evidence type | Tool | Notes |
|---|---|---|---|
| `sast.yml` | `scan.sast` | CodeQL (`security-extended`) | Private repositories need GitHub Code Security |
| `sca.yml` | `scan.sca` | OSV-Scanner | Lockfiles; no lockfile → `inconclusive` |
| `secrets.yml` | `scan.secrets` | gitleaks (redacted) | For organizations without GitHub secret scanning |
| `iac.yml` | `scan.iac` | Checkov | Terraform, Bicep, Kubernetes, Dockerfiles, ... |
| `sbom.yml` | `sbom` | Syft (CycloneDX) | Feeds vulnerability matching and licence checks |
| `container.yml` | `scan.container` | Trivy | Called from your build workflow with the image **digest** |
| `workflow-lint.yml` | `scan.workflow_hardening` | zizmor | Audits the application's own workflows |
| `test-evidence.yml` | `test.security` | your tests (JUnit) | Tag tests with `asvs` / `threat` properties; see below |
| `deploy-evidence.yml` | `deploy.record` | `gh attestation verify` | Call from CD before deploying; records verified + image age |

Status: IMPLEMENTED, linted in CI (actionlint, shellcheck, zizmor), and run on a real GitHub organization, where the
platform accepted their evidence at C3 ([GitHub end to end](../docs/guides/github-e2e.md)). They produce evidence for
you once you publish them in your organization (below).

## How evidence stays trustworthy

Each workflow ends the same way:
1. `aap_evidence.py manifest` writes `evidence-manifest.json`: the evidence type, the tool, the result, and the
   SHA-256 of every file, bound to this repository, commit and run.
2. `actions/attest` signs the manifest with the workflow's own identity (Sigstore, keyless).
3. The bundle is uploaded as the artifact `aap-evidence-<name>`.

The platform then pulls the artifact and re-checks everything against GitHub's API. The run must have called an
**approved commit** of these workflows. The commit, repository and run in the manifest must match. Every file must
match its hash, and the signature must name the approved workflow. Anything else is rejected with a reason code.

`aap_evidence.py` is standard-library Python. `aap pipelines export` copies it **into** each workflow file, so
approving a workflow's commit SHA approves the tool's code too. Nothing is downloaded at run time except pinned actions
and container images (every one pinned to a commit SHA or image digest).

## Set up (once per organization)

Run from `fortproof/backend` in a checkout of the release you deploy. The full walk-through, from installing the
platform to the first application: [Connect your organization](../docs/guide/connect-your-organization.md).

```bash
# 1. Create <org>/security-workflows (internal or public), allow access from the organization's repositories
#    (Settings → Actions → General → Access → "Accessible from repositories in the organization"), clone it next to fortproof/.
# 2. Render the workflows into it; review, commit, tag and push there
uv run aap pipelines export --to ../../security-workflows
#    cd ../../security-workflows && git add . && git commit -s -m "security workflows v1.0.0" && git tag v1.0.0 && git push && git push --tags
# 3. Trust that commit (edits config/trusted-producers.yaml; merge it through review into the rules you deploy)
uv run aap pipelines approve --repository <org>/security-workflows --sha <full commit SHA> --release v1.0.0
# 4. Give each application repository its caller workflow
uv run aap pipelines caller --repository <org>/security-workflows --sha <full commit SHA> --release v1.0.0 \
  > .github/workflows/aap-security.yml   # written into the application repository
```

Upgrades follow the same path: change `pipelines/github/`, export, review, tag, approve. The previous release stays
trusted for 90 days (`retire_after`) so repositories can move over.

## Security test evidence

Your own test job runs the tests and uploads its JUnit XML as an artifact; `test-evidence.yml` packages and signs
it. Link a test to what it verifies with JUnit properties:

```xml
<testcase name="rejects another customer's claim id" classname="ClaimsAuthzTest">
  <properties>
    <property name="asvs" value="V8.2.1,V8.2.2"/>
    <property name="threat" value="TM-07"/>
  </properties>
</testcase>
```

A requirement or threat counts as verified when a linked test passed on the default branch and none failed. The
evidence records that the tests ran in your job: the approved workflow proves what was reported and when, not how
the tests were written, which is why ASVS coverage also counts manual verification.

## Confidence you can expect

| Repository | Runner | Confidence |
|---|---|---|
| Public | GitHub-hosted | **C3** (approved workflow + verified signature) |
| Private, GitHub Enterprise Cloud | GitHub-hosted | **C3** |
| Private, other plans | GitHub-hosted | **C2**: GitHub stores no attestations for these repositories |
| Any | Self-hosted (not ephemeral) | capped at **C2** (`runner_policy`) |

## GitLab

The GitLab CI/CD components are in `pipelines/gitlab/`, set up the same way with `--provider gitlab`:
[GitLab guide](../docs/guides/gitlab-guide.md). GitLab evidence is capped at C2
([ADR-033](../adr/ADR-033-gitlab-evidence-trust.md)).
