# Good first issues (seed list)

Small, self-contained pieces of work, each with existing tests or a pattern to copy. They are opened in the
[issue tracker](https://github.com/cipherfort/fortproof/issues) with the `good first issue` label.

| Issue | Where to start | Pattern to copy |
|---|---|---|
| A ServiceNow ticketing plugin | `examples/plugins/aap-plugin-jsonl`, [plugin guide](../develop/plugins.md) | `connectors/issues.py` (GitLabIssues) |
| A Prowler import plugin (cloud posture) | `services/cloud_sync.py` | `connectors/cloud.py` |
| GitHub Advisory Database as a vulnerability feed | `connectors/vuln_feeds.py` | `OsvClient` |
| More end-of-life product mappings | `config/eol-products.yaml` | existing entries |
| A `financial-services` classification profile | `config/profiles/` | `generic/` |
| Container scanning component for GitLab with verified inputs | `pipelines/gitlab/`, ADR-033 | `connectors/gitlab.render_component` |
| Prometheus metrics endpoint (then a ServiceMonitor in the chart) | `api/app.py` | — |
| Implement a `designed` API operation (e.g. `listTickets`) | `schemas/api/openapi.yaml` (`x-status: designed`) | `api/app.py` list endpoints |
| AWS Security Hub with the platform's own AWS identity (IRSA) instead of an Azure token | `worker/connectors.py` (`aws`) | `connectors/cloud.py` (`SecurityHubClient` takes any boto3 session) |
| Accept SPDX SBOMs by converting them to CycloneDX on ingest | `services/sbom_sync.py`, [ADR-010](../../adr/ADR-010-cyclonedx-vs-spdx.md) | the CycloneDX path |
