# Changelog

All notable changes, newest first. From 0.1.0 on this file is maintained by release-please from Conventional Commit
messages (`feat:`, `fix:`, `docs:` ...); see [RELEASING.md](RELEASING.md).

## 0.1.0 (2026-10-20)

First public preview: the evidence engine, all 48 control evaluators, GitHub and GitLab, shipped security pipelines
and components, built-in vulnerability intelligence, exceptions, assessments, administration, the web UI, the Helm
chart and the Compose evaluation stack. Tested end to end on a real GitHub organization
([guide](docs/guides/github-e2e.md)). See [ROADMAP.md](ROADMAP.md) for what 1.0 adds.

The project was called Attestra before its first release; it was renamed FortProof to avoid a clash with an existing
security product of that name.


### ⚠ BREAKING CHANGES

* evidence manifests and attestations use the predicate type https://fortproof.dev/attestation/evidence/v1; the old one is refused. Nothing was released under the old name.

### Features

* **github:** pick up workflow runs whose webhook never arrived ([#45](https://github.com/cipherfort/fortproof/issues/45)) ([ed1459f](https://github.com/cipherfort/fortproof/commit/ed1459f262c476ac1ca7db4fdc2f08575f531166))
* monthly posture snapshots, trends and dashboard read models (UI-3) ([#34](https://github.com/cipherfort/fortproof/issues/34)) ([b5325b8](https://github.com/cipherfort/fortproof/commit/b5325b88219aa46f9041adc6f9f3f87f9e170329))
* rename the project to FortProof ([#40](https://github.com/cipherfort/fortproof/issues/40)) ([fa06d30](https://github.com/cipherfort/fortproof/commit/fa06d3081c9b7161594270c3060a22c445a04a2a))
* **ui:** controls catalogue, maturity roll-up, supply chain (UI-6) ([#37](https://github.com/cipherfort/fortproof/issues/37)) ([c1086c4](https://github.com/cipherfort/fortproof/commit/c1086c4edac541281f31d3f5d2d97ed9f5d0a405))
* **ui:** evidence explorer with verification chain, global findings (UI-5) ([#36](https://github.com/cipherfort/fortproof/issues/36)) ([6203cc7](https://github.com/cipherfort/fortproof/commit/6203cc7f0af72152b0d0e552916d0e58bd396ba6))
* **ui:** exceptions, assessments, leadership, integrations, admin and onboarding (UI-7) ([#38](https://github.com/cipherfort/fortproof/issues/38)) ([6252661](https://github.com/cipherfort/fortproof/commit/6252661834f5c497c4f830edffb0638041da7fb0))
* **ui:** launch assets, bundle budget, keyboard and reduced-motion checks (UI-8) ([#39](https://github.com/cipherfort/fortproof/issues/39)) ([fa96f90](https://github.com/cipherfort/fortproof/commit/fa96f9026a3cfc49c9bd323e92b8b5b7e8c00776))


### Bug Fixes

* **attestation:** accept the evidence predicate the shipped workflows sign ([#46](https://github.com/cipherfort/fortproof/issues/46)) ([3db0fd0](https://github.com/cipherfort/fortproof/commit/3db0fd07892e70bc4495cc1041ce89b2faed881d))
* **findings:** close dependency findings when the next SBOM drops the component ([#47](https://github.com/cipherfort/fortproof/issues/47)) ([37e8958](https://github.com/cipherfort/fortproof/commit/37e8958357f31175af9e3e64f6db87c432d30349))
* **gitlab-issues:** create labels before the issue so deduplication cannot break ([#30](https://github.com/cipherfort/fortproof/issues/30)) ([372adb5](https://github.com/cipherfort/fortproof/commit/372adb5b0faae0f7aa525a29e68c571e4f4b0f8c))
* **worker:** keep the scheduler sweep running ([#43](https://github.com/cipherfort/fortproof/issues/43)) ([bd734c0](https://github.com/cipherfort/fortproof/commit/bd734c0f654c031b152dfc10f1aa8e7545605e4e))
