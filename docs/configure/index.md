# Configure for your organization

Two kinds of configuration, deliberately separate:

| | What | Where | Changed by |
|---|---|---|---|
| **Settings** | URLs, sign-in, storage, which plugins are switched on | `aap.yaml` ([reference](../reference/settings.md)) or `AAP_*` variables; secrets in the secret store | Operators, per deployment |
| **Rules** | Organization levels, classification, controls, risk model, exception policy, evidence types, trusted producers | `config/` and `catalogue/` in your fork | Pull request with review; every verdict records the rule version it used |

The platform reads the rules from its image at start-up and loads them into the database on every install and
upgrade. To deploy your rules with a released version, build an image on top of the release with them copied in:
[Connect your organization, step 2](../guide/connect-your-organization.md#2-your-rules).

## Organization

`config/organization.yaml` names your levels, for example `company → business unit → team` or `org → group`. Units and
members are managed on the Admin page; a team's `scm_group` links it to a GitHub team or GitLab group for owner
resolution.

## Classification profile

`config/organization.yaml → profile` selects `config/profiles/<name>/classification.yaml`: the questions, answer
labels, points, floor rules and tier boundaries. Shipped: `generic` (default) and `uk-public-sector` (an example).
Copy one to make yours; [the classification standard](../standards/application-classification-standard.md) explains
the model.

## Controls, risk and exceptions

- `catalogue/controls/controls.yaml`: the 48 controls, which tiers they apply to, the evidence each needs and at what
  confidence, and the evaluator parameters. Validate with `tools/catalogue/validate.py`.
- `config/risk-model.yaml`: how a finding's priority is computed ([risk model](../standards/risk-model.md)).
- `config/exception-policy.yaml`: who may approve which exceptions, maximum durations, co-signature tiers, and how
  platform roles map to approver roles.
- `config/trusted-producers.yaml`: which pipeline commits may produce evidence (`aap pipelines approve`).

## Plugins

Each plugin's settings and set-up command are on the Integrations page and in `aap integrations status`. Policy for
integrations (sync intervals, ticket projects, feeds on/off) is in `config/integrations.yaml`.
