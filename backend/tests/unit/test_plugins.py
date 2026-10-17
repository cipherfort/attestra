# SPDX-License-Identifier: Apache-2.0
"""Plugin discovery (ADR-032): third-party plugins are first-class; broken ones are reported, never fatal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from aap.plugins import KINDS, Plugin, RunResult, discover, registry


@dataclass
class FakeEntryPoint:
    name: str
    value: Any
    dist: Any = None

    def load(self) -> Any:
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


@dataclass
class Dist:
    name: str


def test_builtin_plugins_registered_through_the_entry_point():
    r = registry()
    assert {"github", "jira", "dependency_track", "defectdojo", "azure", "aws", "sentinel", "oidc"} <= set(r.plugins)
    assert not r.load_errors
    assert all(p.kind in KINDS for p in r.plugins.values())
    assert {p.key for p in r.scheduled()} >= {"github", "jira", "sentinel"}


def test_third_party_plugin_loads_with_its_source():
    servicenow = Plugin(
        key="servicenow", name="ServiceNow", kind="ticketing", purpose="tickets", run=lambda ctx: RunResult(1)
    )
    r = discover([FakeEntryPoint("servicenow", servicenow, Dist("aap-servicenow"))])
    assert r.plugins["servicenow"].source == "aap-servicenow" and not r.load_errors


def test_broken_plugins_are_reported_not_fatal():
    good = Plugin(key="good", name="Good", kind="siem", purpose="x")
    r = discover(
        [
            FakeEntryPoint("crashes", ImportError("No module named 'splunklib'")),
            FakeEntryPoint("not-a-plugin", object()),
            FakeEntryPoint("dup", [good, good]),
            FakeEntryPoint("ok", Plugin(key="other", name="Other", kind="siem", purpose="y")),
        ]
    )
    assert set(r.load_errors) == {"crashes", "not-a-plugin", "dup"}
    assert "splunklib" in r.load_errors["crashes"] and "already provided" in r.load_errors["dup"]
    assert "other" in r.plugins
    with pytest.raises(KeyError, match="no plugin 'missing'"):
        r.get("missing")


@pytest.mark.parametrize("kwargs", [{"kind": "toaster"}, {"key": "Bad-Key"}, {"key": "1st"}])
def test_invalid_plugin_definitions_rejected(kwargs):
    base = {"key": "x", "name": "X", "kind": "siem", "purpose": "p"}
    with pytest.raises(ValueError):
        Plugin(**{**base, **kwargs})
