# SPDX-License-Identifier: Apache-2.0
"""How to test a plugin: the record is valid and discoverable, and the sink writes whole batches."""

from __future__ import annotations

import json
from types import SimpleNamespace

from aap_plugin_jsonl import PLUGIN, JsonlSink

from aap.plugins import discover


def test_the_platform_discovers_the_plugin_through_its_entry_point():
    ep = SimpleNamespace(name="jsonl", load=lambda: PLUGIN, dist=SimpleNamespace(name="aap-plugin-jsonl"))
    registry = discover([ep])
    assert registry.load_errors == {}
    plugin = registry.get("jsonl")
    assert plugin.kind == "siem" and plugin.env == ("AAP_JSONL_PATH",) and plugin.source == "aap-plugin-jsonl"


def test_sink_appends_one_json_object_per_event(tmp_path):
    path = tmp_path / "events.jsonl"
    sink = JsonlSink(str(path))
    assert sink.send([{"EventId": "1", "EventType": "secret.exposed_active"}, {"EventId": "2"}]) == 2
    assert sink.send([{"EventId": "3"}]) == 1
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["EventId"] for e in lines] == ["1", "2", "3"]
    assert oct(path.stat().st_mode & 0o777) == "0o640"
