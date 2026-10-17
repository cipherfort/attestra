# SPDX-License-Identifier: Apache-2.0
"""CSV export (scoped, audited, injection-safe) and webhook notifications (deduplicated, delivered once)."""

from __future__ import annotations

import csv
import io
import os
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app, csv_cell
from aap.db import transaction
from aap.services import notifications

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def client(engine, bundle, demo):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def rows(resp):
    return list(csv.DictReader(io.StringIO(resp.text)))


def test_findings_export_is_scoped_and_audited(client, engine):
    org = client.get("/api/v1/reports/findings.csv", headers=as_("cpatel"))
    assert org.status_code == 200 and org.headers["content-type"].startswith("text/csv")
    assert "attachment" in org.headers["content-disposition"]
    unit = client.get("/api/v1/reports/findings.csv", headers=as_("dlee"))
    apps_org, apps_unit = {r["application"] for r in rows(org)}, {r["application"] for r in rows(unit)}
    assert apps_unit and apps_unit <= apps_org and "HR Leave Tracker" not in apps_unit  # Benefits only
    assert client.get("/api/v1/reports/findings.csv", headers=as_("ajones")).status_code == 403  # no report.export
    assert client.get("/api/v1/reports/nope.csv", headers=as_("cpatel")).status_code == 404
    controls = client.get("/api/v1/reports/controls.csv", headers=as_("cpatel"))
    assert rows(controls) and {"control", "state", "explanation"} <= set(rows(controls)[0])
    with transaction(engine, "aap_worker") as conn:
        n = conn.execute(text("SELECT count(*) FROM audit_events WHERE action = 'export.findings'")).scalar_one()
    assert n >= 2


def test_csv_cells_cannot_become_formulas():
    assert csv_cell('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert csv_cell("+1") == "'+1" and csv_cell("-cmd") == "'-cmd" and csv_cell("@SUM(A1)") == "'@SUM(A1)"
    assert csv_cell("normal") == "normal" and csv_cell(None) == ""


def test_notifications_are_collected_once_and_delivered(engine, bundle, demo, monkeypatch):
    from aap.worker import connectors

    with transaction(engine, "aap_worker") as conn:
        first = notifications.collect(conn, bundle, datetime.now(UTC), "https://aap.example.org")
        again = notifications.collect(conn, bundle, datetime.now(UTC), "https://aap.example.org")
        assert first >= 1 and again == 0  # stable keys: nobody is told twice
        queued = notifications.pending(conn)
    assert all(e["link"].startswith("https://aap.example.org/#/") for e in queued)

    sent: list[dict] = []
    state = {"down": True}

    class FakeStore:
        def get(self, name):
            return "https://hooks.example.test/T000/B000/XXXX" if name == "notify-webhook-url" else None

    def handler(req: httpx.Request) -> httpx.Response:
        if state["down"]:
            return httpx.Response(503)
        import json

        sent.append(json.loads(req.content))
        return httpx.Response(200, text="ok")

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    down = connectors.webhook(engine, bundle, FakeStore(), {})
    assert down.items == 0 and "HTTP 503" in down.errors[0]  # nothing marked sent while the endpoint is down
    state["down"] = False
    up = connectors.webhook(engine, bundle, FakeStore(), {})
    assert up.items == len(queued) and up.errors == []
    assert all("text" in m and "key" in m for m in sent)
    assert connectors.webhook(engine, bundle, FakeStore(), {}).items == 0  # delivered once

    class HttpStore(FakeStore):
        def get(self, name):
            return "http://insecure.example.test/hook"

    assert "https://" in connectors.webhook(engine, bundle, HttpStore(), {}).errors[0]
