# A tour of the platform

Every screenshot here comes from the demo world (`aap demo seed`): four applications with a year of history, built by the same ingest and evaluation code a real deployment runs. They are regenerated after any UI change with `npm run screenshots` (see `frontend/e2e/docs.spec.ts`), so they always show the current product.

## Overview

The security posture of everything you can see: the share of mandatory controls proven by verified evidence, open P1 findings, findings past their deadline and rejected evidence, with twelve months of history. Below that are SAMM maturity by business function, recent activity, coverage by control domain and application, and the most urgent findings.

![Overview](assets/screenshots/overview-light.webp#only-light)
![Overview](assets/screenshots/overview-dark.webp#only-dark)

## An application

What still needs evidence, why the application is in its tier, and who owns it. The tabs cover controls, findings, evidence, the supply chain (its SBOM, component by component), maturity and activity.

![Application](assets/screenshots/application-light.webp#only-light)
![Application](assets/screenshots/application-dark.webp#only-dark)

## How a piece of evidence was verified

Each accepted record shows its chain: the pipeline run and commit that produced it, the manifest and file hashes, each verification check, its place in the append-only ledger and the confidence it earned. Unsigned pipeline evidence says plainly why it stays at C2.

![Evidence chain](assets/screenshots/evidence-chain-light.webp#only-light)
![Evidence chain](assets/screenshots/evidence-chain-dark.webp#only-dark)

## Forged evidence is refused

A scan result uploaded from a copy of the security workflow kept in the application's own repository is rejected as an untrusted producer. Nothing on this tab counts towards any control.

![Rejected evidence](assets/screenshots/evidence-rejected-light.webp#only-light)
![Rejected evidence](assets/screenshots/evidence-rejected-dark.webp#only-dark)

## Are we affected?

One vulnerability checked against every application's current SBOM. Applications without a current SBOM are listed as possibly affected, never as unaffected.

![Are we affected](assets/screenshots/are-we-affected-light.webp#only-light)
![Are we affected](assets/screenshots/are-we-affected-dark.webp#only-dark)

## Maturity

OWASP SAMM scores computed from evidence and recorded assessments, month by month, and how each practice spreads across applications. It is a distribution, never a league table of applications.

![Maturity](assets/screenshots/maturity-light.webp#only-light)
![Maturity](assets/screenshots/maturity-dark.webp#only-dark)

## The control catalogue

Each control states what counts as proof, which tiers must have it, how it maps to OWASP SAMM, ASVS, NIST SSDF and CSF, and where it stands in each application.

![Control catalogue](assets/screenshots/control-drawer-light.webp#only-light)
![Control catalogue](assets/screenshots/control-drawer-dark.webp#only-dark)

## Exceptions with segregation of duties

An exception for a known-exploited dependency, waiting for the business owner's co-signature before the decision. The required approver follows from the residual risk and the application's tier; the requester and the owning team can never approve their own.

![Exception approval](assets/screenshots/exception-approval-light.webp#only-light)
![Exception approval](assets/screenshots/exception-approval-dark.webp#only-dark)
