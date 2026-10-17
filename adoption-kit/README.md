# Adoption kit

The software is half of an application security programme. The other half is the programme itself: who decides, who is accountable, how teams are onboarded, and how progress is measured.

This kit is a **complete worked example** of that programme, written for one fictional public-sector organization while the platform was being designed. Copy it, then replace the organization-specific parts with your own.

| Folder | What it contains | Adapt first |
|---|---|---|
| [`programme/charter/`](programme/charter/) | Programme charter, business case, project initiation document | Sponsor, scope, budget, success measures |
| [`programme/roadmap/`](programme/roadmap/) | Phased rollout (discovery → thin slice → pilot → rollout by tier) | Dates, pilot applications |
| [`programme/raci/`](programme/raci/) | Who is responsible, accountable, consulted and informed for each activity | Your roles and teams |
| [`programme/raid/`](programme/raid/), [`programme/risk-register/`](programme/risk-register/) | Risks, assumptions, issues and dependencies, with mitigations | Your risks; keep the platform risks (R-18 to R-25) that still apply |
| [`governance/`](governance/) | Strategy, target operating model, governance model, security champions framework, data retention policy, target state, decision log | Decision rights, forums, retention periods |
| [`templates/`](templates/) | **Fill-in templates** with `{{PLACEHOLDERS}}`: programme charter, business case, RACI, governance model, champion framework, and a [90-day rollout playbook](templates/rollout-playbook-90-days.md) tied to the platform's commands | Everything in `{{…}}` |

## How to use it

1. **Start with the decision log** ([`governance/decision-log.md`](governance/decision-log.md)). It lists every decision the platform needs a human to make: tiers, deadlines, risk model, retention, which systems to connect. Work out who in your organization makes each one.
2. **Adapt the charter and business case** for your sponsor. The business case lists cost drivers. Price them against your own infrastructure and time.
3. **Set the platform's rules to match your decisions.** They are data in the platform repository (`config/`, `catalogue/`), changed by pull request: tiers, fix deadlines, exception approvers, maturity targets.
4. **Follow the rollout roadmap:** a thin slice on one repository, a pilot with 3–5 applications, then rollout by tier.

## Status of this material

The `programme/` and `governance/` documents are **a worked example, not requirements**: one organization's answers to questions every organization has to answer. Start from `templates/` and use the example for ideas. The KPI and KRI catalogue the templates refer to is [`docs/standards/kpi-kri-catalogue.md`](../docs/standards/kpi-kri-catalogue.md), generated from `config/metrics.yaml`.
