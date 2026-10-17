# SPDX-License-Identifier: Apache-2.0
"""BFF sign-in against a real OIDC server implementation (navikt/mock-oauth2-server, the local Entra stand-in in
deploy/local). Proves interoperability of discovery, JWKS, PKCE, nonce and the code exchange beyond our own fake.
Opt in: AAP_TEST_SERVICES=1."""

from __future__ import annotations

import os
import subprocess
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from aap.api.app import create_app
from aap.api.oidc import OidcClient, OidcSettings
from aap.config import repo_root

pytestmark = [
    pytest.mark.db,
    pytest.mark.service,
    pytest.mark.skipif(os.environ.get("AAP_TEST_SERVICES") != "1", reason="set AAP_TEST_SERVICES=1"),
]


@pytest.fixture(scope="module")
def issuer():
    name = f"aap-oidc-{uuid.uuid4().hex[:6]}"
    cfg = repo_root() / "deploy/local/oidc.json"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::8090",
            "-e",
            "SERVER_PORT=8090",
            "-e",
            "JSON_CONFIG_PATH=/config/oidc.json",
            "-v",
            f"{cfg}:/config/oidc.json:ro",
            "ghcr.io/navikt/mock-oauth2-server:2.1.10",
        ],
        check=True,
        capture_output=True,
    )
    try:
        port = (
            subprocess.run(["docker", "port", name, "8090/tcp"], capture_output=True, text=True, check=True)
            .stdout.splitlines()[0]
            .rsplit(":", 1)[-1]
        )
        url = f"http://127.0.0.1:{port}/aap"
        for _ in range(60):
            try:
                if httpx.get(f"{url}/.well-known/openid-configuration", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_sign_in_with_a_real_oidc_server(issuer, engine, bundle, loaded, monkeypatch):
    monkeypatch.setenv("AAP_AUTH_MODE", "oidc")
    monkeypatch.setenv("AAP_ENV", "development")
    app = create_app(engine, bundle)
    app.state.oidc = OidcClient(
        OidcSettings(
            issuer, "aap-web", "https://testserver/auth/callback", tenant_id="00000000-0000-4000-8000-00000000000a"
        ),
        client_secret="local-dev-only",
    )
    web = TestClient(app, base_url="https://testserver", follow_redirects=False)
    r = web.get("/auth/login")
    assert r.status_code == 302 and r.headers["location"].startswith(issuer)
    back = httpx.get(r.headers["location"], follow_redirects=False)  # the IdP signs the user in and redirects back
    assert back.status_code == 302 and back.headers["location"].startswith("https://testserver/auth/callback?")
    done = web.get(back.headers["location"].replace("https://testserver", ""))
    assert done.status_code == 302, done.text
    me = web.get("/api/v1/users/me").json()
    assert me["user"]["display_name"] == "Local Developer" and [x["role"] for x in me["roles"]] == ["appsec_engineer"]
