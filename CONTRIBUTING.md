# Contributing

Contributions are welcome: bug reports, plugins for systems we don't support yet, documentation, control catalogue improvements, and fixes.

## Before you start

- **Small fixes:** open a pull request directly.
- **Anything larger** (a new plugin, a schema change, a new control): open an issue first, so we agree the approach before you spend time. Design decisions are recorded as ADRs in [`adr/`](adr/README.md).
- **Security issues:** never in public. See [SECURITY.md](SECURITY.md).

## Reporting a bug

1. Check [open issues](https://github.com/cipherfort/fortproof/issues) first; add to an existing report rather than opening a duplicate.
2. Open a [bug report](https://github.com/cipherfort/fortproof/issues/new?template=bug.yml). Include the version (image tag or commit), how you deployed it (Compose, Helm, local), what you did, what you expected, and what happened, with logs if you have them.
3. Leave out secrets, tokens and personal data. For anything that could be a vulnerability, use [SECURITY.md](SECURITY.md) instead.

Questions that aren't bugs go to [Discussions](https://github.com/cipherfort/fortproof/discussions).

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/), not a contributor licence agreement. Every commit must be signed off, certifying you have the right to contribute it under the project's licences (Apache-2.0 for code, CC BY-SA 4.0 for documentation):

```bash
git commit -s -m "Explain what and why"
```

This adds `Signed-off-by: Your Name <you@example.org>`. A CI check rejects pull requests with unsigned commits.

## Set up a development environment

You need Docker, [uv](https://docs.astral.sh/uv/) and Node.js 22.

```bash
deploy/local/bootstrap.sh            # PostgreSQL, a local OIDC provider, Azurite; add "scanners" for Dependency-Track + DefectDojo
source deploy/local/aap.env
cd backend && uv sync && uv run aap demo seed && uv run aap api --port 8765
cd frontend && npm ci && npm run build   # or: npm run dev (proxies /api to :8765)
```

## Checks your change must pass

These are the same checks CI runs:

```bash
cd backend
uv run ruff check src tests migrations && uv run ruff format --check src tests
uv run mypy
uv run pytest                                  # unit + integration (starts a throwaway PostgreSQL)
AAP_TEST_SERVICES=1 uv run pytest -m service   # optional: real Dependency-Track, DefectDojo, OIDC, Azurite
cd ..
python3 tools/catalogue/validate.py --check
python3 tools/config/validate.py
python3 tools/docs/check_links.py
python3 tools/licenses/check.py
tests/database/run.sh
terraform fmt -check -recursive examples/terraform/azure

cd frontend
npm ci
npm run types:check && npm run build && npm run budget   # generated API types current, typecheck, size budget
# browser tests: start the API with the demo world (README, "For development"), then
E2E_BASE_URL=http://127.0.0.1:8765 npx playwright test   # every page and role, axe WCAG 2.2 AA, keyboard paths
```

Changed the UI? Regenerate the screenshots in the README and on the docs site with `npm run screenshots` and
`npm run screenshots:webp` (needs the demo API running and `cwebp`).

## Rules the code follows

These are invariants, enforced by tests. A pull request that weakens one needs an ADR.

1. **Evidence decides; configuration does not.** A setting that says a scan *should* run never satisfies a control that requires it *did* run.
2. **Fail closed.** An unreadable source produces a recorded gap, never "ok". An unimplemented evaluator reports "not evaluated", never a guessed state.
3. **Ledgers are append-only.** Evidence, evaluations, finding events and audit records are never updated or deleted.
4. **Least privilege everywhere.** Read-only connector scopes; no secrets in repositories, logs, command lines or Terraform state.
5. **No telemetry.** The platform never phones home.

## Plugins

Plugins for new systems (source control, ticketing, SIEM, cloud posture, evidence storage) are the easiest way to contribute, and a plugin can live in its own package. A plugin is an `aap.plugins.Plugin` record published through the `aap.plugins` entry-point group:

```toml
# your package's pyproject.toml
[project.entry-points."aap.plugins"]
servicenow = "aap_servicenow:PLUGIN"
```

The record names its kind, the settings and secrets it needs, its schedule, and a `run(context)` function. The client interfaces each kind should satisfy are in `backend/src/aap/plugins/interfaces.py`. The built-in plugins (`backend/src/aap/plugins/builtin.py`) and their connectors (`backend/src/aap/connectors/`) are worked examples. Every plugin needs:
- tests against recorded API shapes, and a live test where the system can run in a container;
- a set-up command, or Terraform, that creates its least-privilege credentials;
- a documented settings list.

## Style

- **Python:** ruff (lint + format), mypy strict on the whole `aap` package.
- **TypeScript:** `tsc --noEmit` via `npm run build`.
- **Docs:** plain English, short sentences. Describe what the code does today; mark anything not built yet as *Planned* (ADRs use *Proposed* until accepted).
- Match the surrounding code.
