# Releasing

## Versions

Semantic versioning. Before 1.0, minor versions may change behaviour; from 1.0, breaking changes need a major version.
Database migrations are forward-only and each release upgrades from the previous minor (tested from every earlier
migration: `backend/tests/integration/test_upgrade.py`). Support: the latest minor gets fixes; from 1.0 the previous
minor also gets security fixes ([SECURITY.md](SECURITY.md)).

## How a release happens

1. Commits on `main` use Conventional Commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `feat!:` for breaking).
2. `release-please` keeps a release pull request open with `CHANGELOG.md` and the version bumped in
   `backend/pyproject.toml`, `frontend/package.json` and `charts/attestra/Chart.yaml`.
3. A maintainer reviews and merges it. release-please tags the merge commit (`vX.Y.Z`); tags matching `v*` are
   protected by a repository ruleset (only release-please and maintainers can create them, nobody can move or delete
   them).
4. The tag runs [`release.yml`](.github/workflows/release.yml):
   - build the image for amd64 and arm64;
   - scan it, failing on fixable HIGH/CRITICAL findings, before anything is pushed;
   - push it to GHCR with an SBOM;
   - attach a SLSA provenance attestation and a cosign keyless signature;
   - package the chart pinned to the image digest, push it to GHCR (OCI) and sign it;
   - publish a GitHub release with the verification commands.
5. A maintainer verifies the published artifacts (commands in the release notes) before announcing the release.

Git tags are created through the GitHub API and are not GPG-signed; the artifacts users run are signed and carry
provenance, which is what installation verifies.

## Before tagging 1.0

The 1.0 gate (ROADMAP): the independent security review closed out ([docs/security/review-scope.md](docs/security/review-scope.md)),
OpenSSF Best Practices "passing" ([self-assessment](docs/security/openssf-best-practices.md)), Scorecard 7 or higher,
and a new user reaching the demo from "Getting started" on a clean machine within 15 minutes, without help.
