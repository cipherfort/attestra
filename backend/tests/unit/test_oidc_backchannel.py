# SPDX-License-Identifier: Apache-2.0
"""AAP_OIDC_INTERNAL_URL: server-to-server calls go to the internal origin; the issuer is still checked exactly."""

from __future__ import annotations

import httpx
import pytest

from aap.api.oidc import OidcClient, OidcError, OidcSettings

PUBLIC = "http://localhost:8180/realms/aap"


def client(meta_issuer: str = PUBLIC) -> tuple[OidcClient, list[str]]:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        if req.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": meta_issuer,
                    "jwks_uri": f"{PUBLIC}/protocol/openid-connect/certs",
                    "token_endpoint": f"{PUBLIC}/protocol/openid-connect/token",
                    "authorization_endpoint": f"{PUBLIC}/protocol/openid-connect/auth",
                },
            )
        return httpx.Response(200, json={"keys": []})

    s = OidcSettings(PUBLIC, "aap-web", "http://localhost:8000/auth/callback", internal_url="http://keycloak:8180")
    return OidcClient(s, client_secret="x", http=httpx.Client(transport=httpx.MockTransport(handler))), seen


def test_backchannel_rewrites_only_server_calls():
    c, seen = client()
    meta = c.metadata()
    with pytest.raises(Exception):  # an empty key set is refused; only the URL it went to matters here
        c._keys()
    assert seen == [
        "http://keycloak:8180/realms/aap/.well-known/openid-configuration",
        "http://keycloak:8180/realms/aap/protocol/openid-connect/certs",
    ]
    assert meta["authorization_endpoint"].startswith("http://localhost:8180/")  # the browser keeps the public URL
    assert c._backchannel("https://elsewhere.example/x") == "https://elsewhere.example/x"


def test_issuer_is_still_checked_exactly():
    c, _ = client(meta_issuer="http://keycloak:8180/realms/aap")
    with pytest.raises(OidcError, match="does not match"):
        c.metadata()
