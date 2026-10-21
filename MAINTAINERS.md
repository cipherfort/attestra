# Maintainers

| Name | GitHub | Areas |
|---|---|---|
| Michael Lawrence | [@ciphermichael](https://github.com/ciphermichael) | Everything (founding maintainer) |

## Access to sensitive resources

| Resource | What it allows | Who |
|---|---|---|
| GitHub organization `cipherfort` (owner) and repository `cipherfort/fortproof` (admin) | Settings, rulesets, secrets, merging, releases | @ciphermichael |
| GitHub Container Registry packages `fortproof` and `charts/fortproof` | Publishing and changing the image and the chart | @ciphermichael, and the release workflow |
| Release signing | Signing images and charts | No long-lived key exists: the release workflow signs with short-lived keyless certificates (Sigstore), tied to `release.yml` |
| Domain `fortproof.dev` and its DNS | The documentation site and the identifiers in evidence (`https://fortproof.dev/attestation/...`) | @ciphermichael |
| Security reports (private vulnerability reporting, the contact address below) | Reading unpublished vulnerabilities | @ciphermichael |
| OpenSSF Best Practices entry (project 15625) | The project's badge answers | @ciphermichael |

**Code of conduct contact:** [info@cipherfortsecurity.com](mailto:info@cipherfortsecurity.com). Reports are read only by the maintainers and handled under the [Code of Conduct](CODE_OF_CONDUCT.md).

**Security issues:** GitHub private vulnerability reporting first ([SECURITY.md](SECURITY.md)); the same address if you cannot use it.

Looking to help maintain? See [GOVERNANCE.md](GOVERNANCE.md).
