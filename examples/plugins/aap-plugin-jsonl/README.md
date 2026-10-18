# aap-plugin-jsonl (example plugin)

A complete, working plugin for FortProof, kept small on purpose: it sends the platform's curated
security events to a JSON Lines file that a log shipper collects. Read [the plugin developer guide](../../../docs/develop/plugins.md)
first; this package is its worked example.

```bash
cd backend && uv pip install -e ../examples/plugins/aap-plugin-jsonl   # into the platform's environment
AAP_JSONL_PATH=/var/log/aap/events.jsonl uv run aap integrations status   # "SIEM events as JSON Lines" appears
uv run pytest ../examples/plugins/aap-plugin-jsonl/tests
```
