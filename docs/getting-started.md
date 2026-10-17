# Getting started

Goal: the platform running on your machine with the demo world, in about 15 minutes, with nothing but Docker.

```bash
git clone https://github.com/cipherfort/attestra && cd REPO
deploy/compose/setup.sh
```

Open http://localhost:8000. You are sent to the sign-in page (Keycloak, part of the evaluation stack). Sign in as
**appsec** with the password the script printed.

## A five-minute tour

1. **Applications.** Four demo applications with their risk tier, how many mandatory controls are *proven by current
   evidence*, and open findings by priority. Proven means evidence, not configuration: a scanner that is configured
   but has not run on the latest commit does not count.
2. **Open Claims API.** "Why Tier 1?" explains the classification. "Needs attention" lists each failing control with
   the reason and a link to request an exception. Every control row expands to the evidence behind it.
3. **Open a finding.** Its priority is explained (exploited in the wild? internet-facing? which data?). Closing is not
   a button: only a re-scan that no longer reports it closes it.
4. **Are we affected?** Type `CVE-2021-44228`: which applications contain the vulnerable component, at which scope.
5. **Sign out and sign in as `dev`.** An engineer in no team sees nothing. As **admin** (Admin page), add `dev` to the
   Claims team; signed in again, `dev` sees Claims API only.

## Next

| You want to | Read |
|---|---|
| Understand the model (evidence, confidence, controls) | [Security model](security/security-model.md) |
| Use it day to day | [User guide](guide/user-guide.md) |
| Connect your GitHub or GitLab | [Integration bootstrap](operations/integration-bootstrap.md), [GitLab](guides/gitlab-guide.md), [pipelines](../pipelines/README.md) |
| Fit it to your organization | [Configure](configure/index.md) |
| Run it in production | [Install with Helm](install/helm.md) |
| Run a security programme around it | [Adoption kit](../adoption-kit/README.md) |
