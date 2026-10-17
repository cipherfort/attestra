# SPDX-License-Identifier: Apache-2.0
"""A minimal, standards-shaped OIDC provider for tests (httpx MockTransport). Real RSA keys, real JWKS, PKCE checked."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://idp.test/tenant-1/v2.0"
CLIENT_ID = "aap-web"
CLIENT_SECRET = "s3cret"
API_AUDIENCE = "api://aap-api"
TENANT = "11111111-1111-1111-1111-111111111111"


class FakeIdP:
    def __init__(self) -> None:
        self.keys = {"k1": rsa.generate_private_key(public_exponent=65537, key_size=2048)}
        self.active_kid = "k1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.user_claims: dict[str, Any] = {}
        self.token_requests: list[dict[str, list[str]]] = []

    # ------------------------------------------------------------- token minting
    def sign(self, claims: dict[str, Any], kid: str | None = None, key: Any = None, alg: str = "RS256") -> str:
        kid = kid or self.active_kid
        return jwt.encode(claims, key or self.keys[kid], algorithm=alg, headers={"kid": kid})

    def id_token(self, nonce: str, **over: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "pairwise-sub",
            "iat": now,
            "exp": now + 3600,
            "nbf": now,
            "nonce": nonce,
            "tid": TENANT,
            "oid": str(uuid.uuid4()),
            "name": "Test User",
            "preferred_username": "test.user@example.org",
        }
        claims.update(self.user_claims)
        claims.update(over)
        return self.sign(claims)

    def access_token(self, **over: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": API_AUDIENCE,
            "sub": "svc",
            "iat": now,
            "exp": now + 3600,
            "tid": TENANT,
            "oid": str(uuid.uuid4()),
            "azp": "bi-tool",
            "roles": ["Reports.Read"],
        }
        claims.update(over)
        return self.sign(claims)

    # ------------------------------------------------------------- browser step
    def authorize(self, url: str) -> str:
        """What the IdP does after the user signs in: returns the redirect back to the client."""
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"nonce": q["nonce"], "challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"]}
        return f"{q['redirect_uri']}?code={code}&state={q['state']}"

    # ------------------------------------------------------------- HTTP
    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == ISSUER + "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://idp.test/authorize",
                    "token_endpoint": "https://idp.test/token",
                    "jwks_uri": "https://idp.test/keys",
                    "end_session_endpoint": "https://idp.test/logout",
                },
            )
        if url == "https://idp.test/keys":
            keys = []
            for kid, k in self.keys.items():
                jwk = json.loads(RSAAlgorithm.to_jwk(k.public_key()))
                keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
            return httpx.Response(200, json={"keys": keys})
        if url == "https://idp.test/token":
            form = parse_qs(request.content.decode())
            self.token_requests.append(form)
            code = self.codes.pop(form["code"][0], None)
            if code is None or form.get("client_secret", [""])[0] != CLIENT_SECRET:
                return httpx.Response(400, json={"error": "invalid_grant"})
            verifier = form["code_verifier"][0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if challenge != code["challenge"] or form["redirect_uri"][0] != code["redirect_uri"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200, json={"id_token": self.id_token(code["nonce"]), "token_type": "Bearer", "access_token": "opaque"}
            )
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))
