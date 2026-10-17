# Attestation fixtures (public data)

Real Sigstore bundles used to test `aap.connectors.attestation` offline. Nothing here is secret.

| File | Source |
|---|---|
| `gh-cli-v2.102.0-provenance.sigstore.json` | `GET /repos/cli/cli/attestations/sha256:bb766f71…9386` → `bundle_url` (snappy, decompressed). SLSA v1 provenance from `cli/cli/.github/workflows/deployment.yml@refs/heads/trunk`, signed by Sigstore public-good. Subject includes `gh_2.102.0_linux_amd64.tar.gz`. |
| `gh-cli-v2.102.0-release.sigstore.json.sn` | Same query, first result, as served (raw snappy). Used to test decompression. |
| `trusted_root.jsonl` | `gh attestation trusted-root` (2026-10-08): Sigstore public-good and GitHub's Sigstore instance (private repositories). |

Refresh: the certificates in a bundle are checked against the time they were logged, so these fixtures do not expire. If the trust root format changes, re-run the commands above.
| `gh-attestation-verify-output.json` | `gh attestation verify gh_2.102.0_linux_amd64.tar.gz --bundle <provenance bundle> --custom-trusted-root trusted_root.jsonl --repo cli/cli --signer-workflow … --signer-digest … --source-digest … --deny-self-hosted-runners --format json` with no token and an empty `GH_CONFIG_DIR` (gh 2.96.0, offline). Used to test parsing of the gh backend. |

## Why two verification backends

sigstore-python (4.5) requires Rekor transparency-log entries. Bundles from **Sigstore public-good** (public repositories) have them and are verified in-process. Bundles from **GitHub's Sigstore instance** (private/internal repositories, which requires GitHub Enterprise Cloud) carry RFC 3161 timestamps only, and sigstore-python rejects them at parse time. Those are verified by `gh attestation verify` (sigstore-go) offline with the same trust root file. Checked on 2026-10-08.
