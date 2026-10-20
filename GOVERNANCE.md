# Governance

## Roles

| Role | Who | Can |
|---|---|---|
| **Users** | Anyone running the platform | Ask questions, report issues, request features |
| **Contributors** | Anyone with a merged pull request | Everything users can; be invited to triage |
| **Maintainers** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Review and merge, release, manage security reports, decide disputes |

A contributor becomes a maintainer after sustained, high-quality contributions (as a guide, about 3 months), when nominated by a maintainer with no objection from the others within 7 days. Maintainers inactive for 6 months move to emeritus.

## Decisions

- **Day to day:** lazy consensus on the pull request or issue. Any maintainer may merge after one other maintainer approves. With a single maintainer, the maintainer merges after a 48-hour public review window, except for security fixes.
- **Significant changes** (anything that changes an invariant in [CONTRIBUTING.md](CONTRIBUTING.md#rules-the-code-follows), the database schema, the plugin interfaces, the evidence trust model, or the licence): an ADR in [`adr/`](adr/README.md), open for comment for at least 7 days, accepted by a majority of maintainers.
- **Security fixes** may be merged without the review window, and disclosed under [SECURITY.md](SECURITY.md).

## Releases

Semantic versioning. Releases are signed and carry SBOMs and build provenance. Database migrations are forward-only, and each release upgrades from the previous minor release.

## Sponsorship and the commercial boundary

FortProof is sponsored by [CipherFort Security](https://cipherfortsecurity.com), whose founder is the founding
maintainer. So that users, contributors and a future OWASP review can rely on it, these commitments hold:

- **Everything in this repository is open source.** Code is Apache-2.0 and documentation CC BY-SA 4.0. No feature is
  held back from the repository, and there is no "enterprise edition" of anything in it.
- **Security fixes are never held back** for paying customers. They are released and disclosed under
  [SECURITY.md](SECURITY.md) for everyone at the same time.
- **Contributors keep their rights.** Contributions are made under the DCO, not a CLA, so nobody, the sponsor included,
  can relicense them.
- **CipherFort Security sells services around the project**, never the project itself: hosting, support, onboarding,
  training, and optional add-ons that live outside this repository.
- **Decisions follow the process above**, whoever employs the maintainers. The sponsor gets no vote of its own.

## Code of conduct

Everyone in the project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Future

Once the project has external users and more than one active maintainer organization, the maintainers intend to apply for the project to become an OWASP project. That would bring this governance under OWASP's project rules.
