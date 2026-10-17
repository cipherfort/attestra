# OpenSSF Best Practices: self-assessment (passing level)

Status: PREPARED. The badge itself is requested by a maintainer at https://www.bestpractices.dev once the public
repository exists (REQUIRES HUMAN ACTION). This maps each criterion group to where the project meets it.

| Criterion group | Met by |
|---|---|
| Basics: description, interaction, contribution, licence | [README](../../README.md), [CONTRIBUTING](../../CONTRIBUTING.md) (DCO), [LICENSE](../../LICENSE) Apache-2.0, [CODE_OF_CONDUCT](../../CODE_OF_CONDUCT.md), [GOVERNANCE](../../GOVERNANCE.md) |
| Documentation | Docs site (MkDocs), install guides, architecture, API contract, ADRs |
| Other: HTTPS, discussion, English | GitHub (HTTPS), issues and discussions |
| Change control: public repo, unique versioning, release notes | Git; semantic versions; `CHANGELOG.md` by release-please ([RELEASING](../../RELEASING.md)) |
| Reporting: bug and vulnerability process, response | Issue templates; [SECURITY.md](../../SECURITY.md) (private reporting, response targets) |
| Quality: build, automated tests, new-functionality tests, warnings | CI: ruff, mypy (strict where it matters), 330+ tests, contract fuzzing, Helm install/upgrade on kind; tests required with changes (CONTRIBUTING) |
| Security: secure design knowledge, crypto practices | Threat model, ADRs; standard libraries only for crypto (cryptography, sigstore); no custom crypto; TLS for every outbound connection |
| Secured delivery against MITM | Signed images and chart (cosign), SLSA provenance, HTTPS only |
| Publicly known vulnerabilities fixed | Dependabot (3-day cooldown); CI fails on known vulnerabilities in runtime dependencies (`pip-audit`, `npm audit`); Trivy scan of the image before release |
| Static analysis | CodeQL (`codeql.yml`), ruff security rules (S), Checkov for Terraform, zizmor for workflows |
| Dynamic analysis | Property-based fuzzing of every untrusted-input parser (CI and nightly), Schemathesis against the API |
