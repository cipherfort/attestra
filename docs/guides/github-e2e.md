# End-to-end test on a real GitHub organization

This is how the GitHub path was proven on a real organization (`cipherfort`) on 2026-10-20, and how to repeat it on
yours. It covers the whole chain: the shipped workflows run in an application repository, the platform verifies
their signed evidence, a vulnerable dependency becomes a finding, and the fix closes it.

## Result

| Step | What happened |
|---|---|
| Register | `aap apps register cipherfort/fortproof-e2e-app` read `.security/application.yaml` through the GitHub App: `APP-00001`, Tier 4, approved automatically |
| Webhook | A signed `workflow_run.completed` delivery was accepted (202); the same delivery with a forged signature was refused (401) |
| Evidence | All 6 bundles from security-workflows v2.0.0 (SAST, SCA, secrets, IaC, SBOM, workflow hardening) accepted at **C3**: approved workflow at an approved commit, Sigstore signature verified, GitHub-hosted runner |
| Older runs | Runs from the pre-rename workflows (v1.0.0) were refused as `SCHEMA_INVALID`: their manifests carry the old identifier |
| Finding | The OSV feed matched PyYAML 5.3 in the verified SBOM: CVE-2020-14343 and CVE-2020-1747, P4 (Tier 4, internal, not known to be exploited) |
| Fix | PyYAML upgraded to 6.0.2 and pushed. With no webhook delivered, the GitHub connector's next run found the completed run and queued it; its evidence was accepted at C3 |
| Closure | Both findings closed, with the C3 SBOM as closure evidence |
| Controls | 10 satisfied, 6 not satisfied, 2 stale, 1 no evidence, 29 not applicable at Tier 4 |

## What it found

Six defects the unit and integration tests had not caught, each fixed with a test (most use this run's real data as
fixtures):

1. The verifier accepted only SLSA provenance, but the shipped workflows sign with the FortProof evidence predicate,
   so every signed bundle was rejected (#46).
2. Workflow runs were collected only from webhooks; a missed delivery lost that evidence (#45).
3. The reconciliation window counted one-repository syncs, which skipped runs (#45).
4. Dependency findings never closed when a newer SBOM dropped the component (#47).
5. An SBOM ingested late could replace a newer one as current (#47).
6. SBOM quality counted the files Syft lists, so real SBOMs were inconclusive (#47).

## Repeat it on your organization

You need: a GitHub organization you administer, Docker, and the [development set-up](../../CONTRIBUTING.md).

1. **The security workflows.** Create `<org>/security-workflows`, render the shipped workflows into it and release them:
   ```bash
   uv run aap pipelines export --to ../security-workflows
   # commit, push, tag (for example v1.0.0), then trust that commit:
   uv run aap pipelines approve --repository <org>/security-workflows --sha <commit> --release v1.0.0
   ```
2. **An application repository** with `.security/application.yaml` ([template](../../templates/repo-contract/)), a
   deliberately vulnerable dependency (for example `PyYAML==5.3` in `requirements.txt`), and the caller workflow:
   `uv run aap pipelines caller`. Public repositories get signed (C3) evidence; private ones need GitHub Enterprise
   Cloud for that, otherwise evidence stays at C2.
3. **The GitHub App.** From `backend/`:
   ```bash
   uv run aap bootstrap github-app --org <org> --name "FortProof" --port 8770
   ```
   then install it on both repositories (**Only select repositories**). Set `AAP_GITHUB_APP_CLIENT_ID` (printed by the
   command) and `AAP_GITHUB_ORG`.
4. **Register and collect.** Create the organization unit the contract names (Admin page, or `config/organization.yaml`),
   then:
   ```bash
   uv run aap apps register <org>/<app-repo>
   uv run aap integrations run github    # settings, and every completed run whose webhook did not arrive
   uv run aap integrations run osv       # vulnerability matches against the verified SBOM
   uv run aap worker --once              # ingest, evaluate, score
   ```
   With a public webhook endpoint (`aap hook` behind your ingress), runs are ingested as they finish instead.
5. **Fix and verify.** Upgrade the dependency, push, wait for the workflows, run the GitHub connector and the worker
   again. The findings close, with the new SBOM as closure evidence; the application page and **Evidence** show how
   each record was verified.
