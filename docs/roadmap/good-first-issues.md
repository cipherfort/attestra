# Good first issues (seed list)

Issues to open when the public repository exists, each small, self-contained and covered by existing tests or a
pattern to copy. Label them `good first issue`.

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
