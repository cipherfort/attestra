# SPDX-License-Identifier: Apache-2.0
"""The UI is served with real URLs: client routes get index.html, while missing assets and unknown API paths stay 404."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from aap.api.app import spa_static_files


def _client(tmp_path) -> TestClient:
    (tmp_path / "index.html").write_text("<!doctype html><title>ui</title>")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    app = FastAPI()

    @app.get("/api/v1/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    app.mount("/", spa_static_files(tmp_path), name="ui")
    return TestClient(app)


def test_client_routes_get_the_app(tmp_path):
    c = _client(tmp_path)
    for path in ("/", "/apps", "/apps/APP-00001/controls", "/settings/admin/units"):
        r = c.get(path)
        assert r.status_code == 200 and "<title>ui</title>" in r.text, path


def test_assets_and_api_are_not_masked(tmp_path):
    c = _client(tmp_path)
    assert c.get("/assets/app.js").text == "console.log(1)"
    assert c.get("/assets/missing.js").status_code == 404  # a missing asset is not answered with HTML
    assert c.get("/favicon.ico").status_code == 404
    assert c.get("/api/v1/health/live").json() == {"status": "ok"}
    assert c.get("/api/v1/nope").status_code == 404  # unknown API paths stay 404, never the app
    assert c.get("/auth/unknown").status_code == 404
