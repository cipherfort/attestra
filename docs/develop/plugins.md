# Writing a plugin

Everything that talks to an outside system is a plugin: source control, sign-in, ticketing, vulnerability data, cloud
posture, SIEM, notifications, evidence storage, secrets. The built-in integrations are plugins too, registered the same
way yours will be. The worked example is [`examples/plugins/aap-plugin-jsonl`](../../examples/plugins/aap-plugin-jsonl/README.md),
which is tested in CI.

## The contract

A plugin is a Python package that publishes a `Plugin` record through the `aap.plugins` entry-point group:

```toml
[project.entry-points."aap.plugins"]
servicenow = "aap_servicenow:PLUGIN"     # one Plugin, or a list of them
```

```python
from aap.plugins import Plugin, RunContext, RunResult

def run(ctx: RunContext) -> RunResult:     # ctx: engine, bundle (governed config), secrets, blobs, payload
    ...                                    # do the work through the platform's services
    return RunResult(items=12, gaps={}, errors=[])

PLUGIN = Plugin(
    key="servicenow",                      # [a-z][a-z0-9_]*, unique; also the name in connector_runs
    name="ServiceNow",
    kind="ticketing",                      # scm, identity, ticketing, vuln_intel, workbench, cloud_posture,
                                           # siem, notification, evidence_store, secrets
    purpose="Remediation tickets in ServiceNow",
    env=("AAP_SERVICENOW_URL",),           # settings that must be present (names only)
    secrets=("servicenow-token",),         # secret-store names that must be present
    bootstrap="how an operator sets it up",
    interval="servicenow.sync_interval",   # path in config/integrations.yaml; None = runs on demand only
    run=run,
)
```

The platform shows the plugin on the Integrations page as **configured** only when every `env` setting and `secrets`
entry is present; until then it never runs and its evidence types stay NO_EVIDENCE. A plugin that fails to import is
listed with its error and the platform keeps running.

## Interfaces by kind

The client a plugin wraps should satisfy the protocol for its kind in
[`aap/plugins/interfaces.py`](../../backend/src/aap/plugins/interfaces.py): `TicketSystem`, `CloudPosture`,
`SiemSink`, `VulnFeed`, `EvidenceBlobStore`, `SecretStore`, `GitHubClient`. Then the platform's services do the rest:

| Kind | Hand your client to | Example |
|---|---|---|
| ticketing | `services.ticketing.sync(conn, client, policy, url, now)` | `connectors/issues.py` (GitHub/GitLab Issues) |
| siem | `services.siem_export.derive(...)` then `dispatch(conn, sink)` | `connectors/siem_sinks.py`, the example plugin |
| cloud_posture | `services.cloud_sync` | `connectors/cloud.py` |
| vuln_intel | `services.vuln_feeds` (OSV-style matching) | `connectors/vuln_feeds.py` |

## Rules your plugin must keep

These are the platform's invariants ([CONTRIBUTING](../../CONTRIBUTING.md)); a plugin that breaks one cannot be listed:

1. **Fail closed.** Anything you cannot read is a gap (`RunResult.gaps`), never a default "ok".
2. **Evidence comes from the worker, through `evidence_store.insert_evidence`, with an honest confidence.** A
   setting you read through an API is C1; something the external system executed itself may be C3; you never claim
   more than your source can prove.
3. **Least privilege.** Ask for read-only credentials; if you must write (tickets, messages), use a separate
   credential and send identifiers and links, not finding details.
4. **No telemetry, no network calls outside `run`.** Importing your module must not do I/O.
5. **One SIEM sink at a time.** SIEM plugins call `aap.worker.connectors.other_siem_sinks(key)` and refuse to run
   when another sink is configured.

## Testing

- Unit tests against recorded API responses (`httpx.MockTransport`).
- A discovery test: `aap.plugins.discover([entry_point])` returns your plugin with no load errors (see the example).
- A live test against the real system in a container where one exists, marked `service` (opt-in).
- Install into the platform for an end-to-end check: `uv run --with-editable path/to/plugin aap integrations status`.

## Publishing

Name it `aap-plugin-<system>`, licence it compatibly (Apache-2.0 recommended), document its settings, secrets and the
least-privilege set-up for the external system. Open an issue to have it listed.
