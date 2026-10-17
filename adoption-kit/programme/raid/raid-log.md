# RAID Log

| | |
|---|---|
| Status | Initial (2026-10-07). Maintained by the governance analyst from Phase 0. Reviewed fortnightly. |
| Risks | Held in the [risk register](../risk-register/risk-register.md) (R-01…R-20). Not duplicated here. |

## Assumptions

| ID | Assumption | Owner | Validate by | Status | Impact if wrong |
|---|---|---|---|---|---|
| A-01 | ~~GitHub Enterprise Cloud with GHAS covers all in-scope orgs~~ **Not assumed (ADR-031).** The project creates its organization; the plan is decision D-018 | Programme owner | Phase 0 wk 2 | Replaced by D-018 | Free/Team: private-repo evidence capped at C2, no org rulesets; GHAS features per plan |
| A-02 | Entra ID is the workforce IdP | Platform lead | Phase 0 wk 1 | Open | Sign-in is standard OIDC (tested against a non-Microsoft OIDC server); another IdP needs only the settings, not code. Entra apps are created by the project (`modules/entra`). |
| A-03 | Azure UK South hosts the platform ~~in the existing landing zone~~; **the platform creates its own network** (ADR-031) | Platform lead | Phase 0 wk 2 | Open (region only) | Region variable only |
| A-04 | Jira Cloud is the ticketing system. **The project creates the site/project** (`aap bootstrap jira`) | Platform lead | Phase 0 wk 2 | Open | Another tracker needs an adapter behind the same interface (ADR-018) |
| A-05 | Artifact attestations available for private/internal repos | Platform tech lead | 2026-10-08 | **Resolved**: public repos yes (Sigstore public-good, verified in-process); private/internal repos need **GitHub Enterprise Cloud** (GitHub's Sigstore instance, verified with `gh attestation verify`). Both backends implemented and tested against a real attestation. | Without Enterprise Cloud, private-repo evidence is C2 (D-018) |
| A-06 | 100–500 apps, 300–2,000 repos | AppSec | Phase 0 wk 4 (inventory) | Open | Sizing, rollout waves |
| A-07 | An information classification scheme exists | Information governance | Phase 0 wk 3 | Open | Classification labels |
| A-08 | Sentinel is the SIEM. **The project deploys it** (`modules/sentinel`) | Platform lead | Phase 0 wk 1 | Open | Exabeam only if the organization adopts it (PROPOSED adapter) |
| A-09 | Org rulesets support "require workflows" on the org's plan | Platform lead | Phase 0 wk 2 | Replaced by D-018 | Repository rulesets otherwise (applied per repo at onboarding) |
| A-10 | Teams can allocate ~10% of one engineer as champion | Engineering leadership | Phase 0 | Open | Champions model |

## Issues

| ID | Issue | Raised | Owner | Action | Status |
|---|---|---|---|---|---|
| I-01 | DefectDojo and Dependency-Track scaffold not yet deployed; MVP networking/DB weaknesses (CS-1…CS-7) | 2026-10-07 | Platform lead | Superseded by ADR-031: the project deploys its own pinned DT/DD (`modules/scanners`); the scaffold is reference only | Closed 2026-10-08 |
| I-02 | Every onboarded repo holds DD/DT API keys (CS-1) | 2026-10-07 | Platform PO | Not applicable to a fresh project: no repository is onboarded with keys; the pull model (ADR-005) is the only path | Closed 2026-10-08 |
| I-03 | Local Docker VM disk full on the design workstation (schema tests use tmpfs as a workaround) | 2026-10-07 | Tech lead | Build cache pruned with the owner's approval (20.8 GB) | Closed 2026-10-08 |
| I-04 | Design repository is not yet under git / not on GitHub, so CI has not run | 2026-10-07 | Programme owner | Create the repo in the org, push, enable branch protection | Open |

## Dependencies

| ID | Dependency | Provider | Needed by | Status |
|---|---|---|---|---|
| D-01 | GitHub App created and installed | Project: GitHub org owner (`aap bootstrap github-app`, runbook section 7) | Phase 1 wk 4 | Code IMPLEMENTED; human step pending |
| D-02 | Org Actions policy, rulesets, `security-workflows` repo | Project: GitHub org owner (`examples/terraform/azure/envs/github`, section 6) | Phase 3 | Code IMPLEMENTED; apply pending |
| D-03 | Entra app registrations, app roles, groups, federated credential; PIM, Conditional Access | Project: tenant admin (`modules/entra`, section 2, section 5) | Phase 1 wk 2 | Code IMPLEMENTED; apply pending. PIM/CA policies are tenant settings set by the same admin |
| D-04 | VNet, private DNS, private endpoints | Project (`modules/platform`, section 2) | Phase 1 wk 2 | Code IMPLEMENTED; apply pending |
| D-05 | Reader + Security Reader at chosen scopes | Project: User Access Administrator (`modules/azure-reader`); scopes = D-015 | Phase 8 | Code IMPLEMENTED |
| D-06 | AWS IAM OIDC provider + Security Hub reader role | Project: AWS admin (`envs/aws`, section 8) | Phase 8 | Code IMPLEMENTED |
| D-07 | Sentinel table, DCR/DCE, analytics rules | Project (`modules/sentinel`, section 2); event list approval: SOC lead (section 10) | Phase 8 | Code IMPLEMENTED; approval pending |
| D-08 | Jira site, project, issue security, service account token | Project: Jira site admin (`aap bootstrap jira`, section 9) | Phase 8 | Code IMPLEMENTED; human step pending |
| D-09 | DPIA screening and lawful basis | DPO | Before pilot | Not requested |
| D-10 | Licence policy approval | Legal | Phase 5 | Not requested |
| D-11 | Retention schedule approval | Records management | Before WORM lock | Not requested |
| D-12 | LMS export (training completions) | HR / L&D, if an LMS exists | Phase 6 | Not assumed: training evidence is manual (M1/M2) until an LMS connector is justified |
