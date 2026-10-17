# SPDX-License-Identifier: Apache-2.0
"""Bootstrap commands without the external systems: manifest flow, secret handling, no secrets on stdout."""

import html
import json
import re
import socket
import stat
import threading
import time

import httpx
import pytest

from aap import bootstrap
from aap.secrets import FileSecretStore, SecretError


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_github_manifest_is_read_only_and_local_has_no_webhook():
    m = bootstrap.github_manifest("acme", "AAP", None, "http://127.0.0.1:1/callback")
    assert set(m["default_permissions"].values()) == {"read"} and m["public"] is False
    assert m["hook_attributes"]["active"] is False and m["default_events"] == []
    deployed = bootstrap.github_manifest("acme", "AAP", "https://aap.example.org", "http://127.0.0.1:1/callback")
    assert deployed["hook_attributes"] == {"url": "https://aap.example.org/github/webhook", "active": True}
    assert "workflow_run" in deployed["default_events"]


def test_manifest_flow_stores_credentials_and_rejects_forged_state(tmp_path, capsys):
    store = FileSecretStore(tmp_path / "secrets")
    port = _free_port()
    out: dict = {}

    def run():
        out.update(
            bootstrap.github_app(
                "acme",
                "AAP",
                None,
                port=port,
                open_browser=False,
                store=store,
                exchange=lambda code: {
                    "id": 42,
                    "slug": "aap-acme",
                    "client_id": "Iv23x",
                    "client_secret": "cs",
                    "webhook_secret": "wh",
                    "pem": "-----BEGIN RSA PRIVATE KEY-----\nX\n",
                },
            )
        )

    t = threading.Thread(target=run)
    t.start()
    for _ in range(50):
        try:
            page = httpx.get(f"http://127.0.0.1:{port}/").text
            break
        except httpx.HTTPError:
            time.sleep(0.05)
    action = html.unescape(re.search(r'action="([^"]+)"', page)[1])
    assert action.startswith("https://github.com/organizations/acme/settings/apps/new?state=")
    manifest = json.loads(html.unescape(re.search(r'name="manifest" value="([^"]+)"', page)[1]))
    assert manifest["redirect_url"] == f"http://127.0.0.1:{port}/callback"
    assert httpx.get(f"http://127.0.0.1:{port}/callback?code=c&state=forged").status_code == 400
    state = action.split("state=")[1]
    assert httpx.get(f"http://127.0.0.1:{port}/callback?code=c&state={state}").status_code == 200
    t.join(5)
    assert out["AAP_GITHUB_APP_CLIENT_ID"] == "Iv23x" and out["install_url"].endswith(
        "/apps/aap-acme/installations/new"
    )
    assert store.get("github-app-private-key").startswith("-----BEGIN") and store.get("github-webhook-secret") == "wh"
    printed = capsys.readouterr().out
    assert "BEGIN RSA" not in printed and "wh" not in printed.split() and "cs" not in printed.split()


def test_file_store_refuses_loose_permissions(tmp_path):
    store = FileSecretStore(tmp_path / "s")
    store.put("x", "v")
    path = tmp_path / "s" / "x"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o644)
    with pytest.raises(SecretError, match="readable by other users"):
        store.get("x")
    with pytest.raises(SecretError):
        store.put("../escape", "v")


def test_file_store_refused_in_production(monkeypatch):
    from aap.secrets import secret_store

    monkeypatch.setenv("AAP_ENV", "production")
    monkeypatch.setenv("AAP_SECRETS_BACKEND", "file")
    with pytest.raises(SecretError, match="not permitted"):
        secret_store()


def test_secrets_never_come_from_argv(monkeypatch):
    monkeypatch.setenv("JIRA_TOKEN", "t0k")
    assert bootstrap._secret_from("JIRA_TOKEN", "x") == "t0k"
    monkeypatch.setenv("EMPTY", "")
    with pytest.raises(SystemExit):
        bootstrap._secret_from("EMPTY", "x")
