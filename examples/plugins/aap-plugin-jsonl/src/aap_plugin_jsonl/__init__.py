# SPDX-License-Identifier: Apache-2.0
"""Example plugin: a SIEM sink that appends the platform's curated security events to a JSON Lines file, for a log
shipper (Fluent Bit, Vector, the Elastic agent ...) to collect. Settings: AAP_JSONL_PATH (required).

Everything a plugin needs is here:
* a `Plugin` record (kind, the settings and secrets it needs, how to set it up, its schedule, its `run` function);
* `run(ctx)` that does the work through the platform's own services and returns a `RunResult`;
* failure handling that leaves the events queued, so a full disk loses nothing.
"""

from __future__ import annotations

import json
import os
from typing import Any

from aap.plugins import Plugin, RunContext, RunResult


class JsonlSink:
    """Implements aap.plugins.interfaces.SiemSink: send(rows) → count, raising on failure."""

    def __init__(self, path: str):
        self.path = path

    def send(self, rows: list[dict[str, Any]]) -> int:
        # one write per batch: either the whole batch reaches the file or the rows stay queued
        data = "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, data.encode())
        finally:
            os.close(fd)
        return len(rows)


def run(ctx: RunContext) -> RunResult:
    from datetime import UTC, datetime

    from aap.db import transaction
    from aap.services import siem_export
    from aap.worker.connectors import other_siem_sinks

    if others := other_siem_sinks("jsonl"):  # events leave through exactly one sink
        return RunResult(errors=[f"more than one SIEM sink is configured (jsonl, {', '.join(others)}): keep one"])
    sink = JsonlSink(os.environ["AAP_JSONL_PATH"])
    with transaction(ctx.engine, "aap_worker") as conn:
        siem_export.derive(conn, ctx.bundle.doc("siem_events"), datetime.now(UTC), os.environ.get("AAP_PUBLIC_URL", ""))
    try:
        with transaction(ctx.engine, "aap_worker") as conn:
            sent, error = siem_export.dispatch(conn, sink)
    except OSError as e:
        return RunResult(errors=[f"cannot write {sink.path}: {e.strerror}"])
    return RunResult(sent, {}, [error] if error else [])


PLUGIN = Plugin(
    key="jsonl",
    name="SIEM events as JSON Lines (example plugin)",
    kind="siem",
    purpose="Curated security events appended to a file for a log shipper",
    env=("AAP_JSONL_PATH",),
    bootstrap="pip install aap-plugin-jsonl; set AAP_JSONL_PATH to a file your log shipper reads",
    evidence=(),
    interval="siem.dispatch_interval",
    run=run,
    source="aap-plugin-jsonl",
)
