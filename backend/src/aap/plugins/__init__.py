# SPDX-License-Identifier: Apache-2.0
"""Plugins: every integration with an outside system (ADR-032).

A plugin is a `Plugin` record published through the Python entry-point group `aap.plugins`. An entry point may
resolve to one Plugin or a list of them. The built-in integrations register exactly the same way
(`aap.plugins.builtin:PLUGINS` in pyproject.toml), so a third-party package is a first-class citizen:

    [project.entry-points."aap.plugins"]
    servicenow = "aap_servicenow:PLUGIN"

The core never imports a plugin directly. It asks the registry what is installed, whether each one is configured
(its settings and secrets are present), and runs it on its schedule. A plugin that fails to load is reported, not
fatal. Interfaces a plugin's client should satisfy are in `aap.plugins.interfaces`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.metadata import entry_points
from typing import Any

log = logging.getLogger("aap.plugins")

GROUP = "aap.plugins"
KINDS = frozenset(
    {
        "scm",
        "identity",
        "ticketing",
        "vuln_intel",
        "workbench",
        "cloud_posture",
        "siem",
        "evidence_store",
        "secrets",
        "notification",
    }
)


@dataclass
class RunResult:
    items: int = 0
    gaps: dict[str, Any] = field(default_factory=dict)  # what could not be read, and why (never silently "ok")
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunContext:
    engine: Any  # sqlalchemy Engine
    bundle: Any  # aap.config.ConfigBundle
    secrets: Any  # aap.secrets.SecretStore
    blobs: Any  # aap.blobstore.EvidenceBlobStore
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class Plugin:
    key: str  # unique, [a-z][a-z0-9_]*; also the connector_runs.connector value
    name: str
    kind: str  # one of KINDS
    purpose: str
    env: tuple[str, ...] = ()  # settings that must be present (AAP_*), names only
    secrets: tuple[str, ...] = ()  # secret-store names that must be present
    bootstrap: str = ""  # how to set it up (a command or a Terraform module)
    evidence: tuple[str, ...] = ()  # evidence types it produces (for the UI)
    interval: str | None = None  # path in config/integrations.yaml to its sync interval; None = not scheduled
    run: Callable[[RunContext], RunResult] | None = None
    source: str = "builtin"  # the distribution that provided it

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"plugin {self.key}: unknown kind {self.kind!r} (one of {sorted(KINDS)})")
        if not self.key.replace("_", "").isalnum() or not self.key[:1].isalpha() or self.key != self.key.lower():
            raise ValueError(f"plugin key {self.key!r} must match [a-z][a-z0-9_]*")


@dataclass(frozen=True)
class Registry:
    plugins: dict[str, Plugin]
    load_errors: dict[str, str]  # entry point name → error

    def get(self, key: str) -> Plugin:
        if key not in self.plugins:
            raise KeyError(f"no plugin {key!r} is installed (installed: {', '.join(sorted(self.plugins)) or 'none'})")
        return self.plugins[key]

    def scheduled(self) -> list[Plugin]:
        return [p for p in self.plugins.values() if p.interval and p.run]


def discover(eps: Any = None) -> Registry:
    """Load every `aap.plugins` entry point. Duplicate keys: the first one loaded wins and the rest are errors."""
    plugins: dict[str, Plugin] = {}
    errors: dict[str, str] = {}
    for ep in sorted(eps if eps is not None else entry_points(group=GROUP), key=lambda e: e.name):
        try:
            loaded = ep.load()
            items = loaded if isinstance(loaded, (list, tuple)) else [loaded]
            dist = getattr(getattr(ep, "dist", None), "name", None) or ep.name
            for item in items:
                if not isinstance(item, Plugin):
                    raise TypeError(f"{type(item).__name__} is not an aap.plugins.Plugin")
                if item.key in plugins:
                    raise ValueError(f"plugin key {item.key!r} is already provided by {plugins[item.key].source}")
                plugins[item.key] = item if item.source != "builtin" or dist == "aap" else _with_source(item, dist)
        except Exception as e:  # a broken plugin must not take the platform down
            errors[ep.name] = f"{type(e).__name__}: {e}"[:300]
            log.error("plugin entry point %s failed to load: %s", ep.name, errors[ep.name])
    return Registry(plugins, errors)


def _with_source(p: Plugin, source: str) -> Plugin:
    from dataclasses import replace

    return replace(p, source=source)


@lru_cache(maxsize=1)
def registry() -> Registry:
    return discover()
