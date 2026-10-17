# SPDX-License-Identifier: Apache-2.0
"""GitHub App authentication (ADR-005, ADR-015).

The platform's GitHub App is created by `aap bootstrap github-app` (manifest flow: one click by an organisation owner,
see docs/operations/integration-bootstrap.md). This module turns its identity into short-lived installation tokens:

    app JWT (RS256, ≤ 10 min, iss = client id)  →  POST /app/installations/{id}/access_tokens  →  token (1 h)

The JWT is signed by a `Signer`: `KeyVaultSigner` signs inside Key Vault with a non-exportable key (production; the
private key never enters process memory), `PemSigner` uses a local PEM file (development). Installation tokens are
requested with **read-only** permissions narrower than the App's grant, cached, and refreshed 5 minutes before expiry.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

import httpx

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

# What installation tokens may do. A subset of the App's manifest permissions (bootstrap/github_app.py): every token
# the platform holds is read-only, even if the App were ever granted more.
TOKEN_PERMISSIONS: Mapping[str, str] = {
    "metadata": "read",
    "contents": "read",
    "actions": "read",
    "administration": "read",
    "secret_scanning_alerts": "read",
    "security_events": "read",
    "vulnerability_alerts": "read",
    "environments": "read",
    "secrets": "read",  # names only: the API never returns secret values
    "attestations": "read",
    "members": "read",
}


class Signer(Protocol):
    def sign_rs256(self, message: bytes) -> bytes: ...


class PemSigner:
    def __init__(self, pem: str | bytes):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = serialization.load_pem_private_key(pem.encode() if isinstance(pem, str) else pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("GitHub App keys are RSA")
        self._key = key

    def sign_rs256(self, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())


class KeyVaultSigner:
    """Signs with a Key Vault key (`/keys/<name>`). The platform identity needs only `Key Vault Crypto User`."""

    def __init__(self, key_id: str, credential: Any):
        from azure.keyvault.keys.crypto import CryptographyClient

        self._client = CryptographyClient(key_id, credential=credential)

    def sign_rs256(self, message: bytes) -> bytes:
        from azure.keyvault.keys.crypto import SignatureAlgorithm

        return bytes(self._client.sign(SignatureAlgorithm.rs256, hashlib.sha256(message).digest()).signature)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(client_id: str, signer: Signer, now: float | None = None) -> str:
    """GitHub accepts iat up to 60 s in the past (clock skew) and exp at most 10 minutes after iat."""
    now = time.time() if now is None else now
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iat": int(now) - 60, "exp": int(now) + 540, "iss": client_id}
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_b64url(signer.sign_rs256(signing_input))}"


@dataclass
class _Token:
    value: str
    expires_at: float


class GitHubAppAuth:
    def __init__(
        self,
        client_id: str,
        signer: Signer,
        base_url: str = API,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
        permissions: Mapping[str, str] = TOKEN_PERMISSIONS,
    ):
        self.client_id = client_id
        self._signer = signer
        self._http = http or httpx.Client(base_url=base_url, timeout=30.0, follow_redirects=False)
        self._clock = clock
        self._permissions = dict(permissions)
        self._tokens: dict[int, _Token] = {}
        self._installations: dict[str, int] = {}
        self._lock = threading.Lock()

    def _app_headers(self) -> dict[str, str]:
        return {**HEADERS, "Authorization": f"Bearer {app_jwt(self.client_id, self._signer, self._clock())}"}

    def app(self) -> dict[str, Any]:
        r = self._http.get("/app", headers=self._app_headers())
        r.raise_for_status()
        return dict(r.json())

    def installations(self) -> list[dict[str, Any]]:
        r = self._http.get("/app/installations", headers=self._app_headers(), params={"per_page": 100})
        r.raise_for_status()
        return list(r.json())

    def installation_id(self, owner: str) -> int:
        if owner not in self._installations:
            r = self._http.get(f"/orgs/{owner}/installation", headers=self._app_headers())
            if r.status_code == 404:
                r = self._http.get(f"/users/{owner}/installation", headers=self._app_headers())
            if r.status_code == 404:
                raise LookupError(f"the GitHub App is not installed on {owner!r}")
            r.raise_for_status()
            self._installations[owner] = int(r.json()["id"])
        return self._installations[owner]

    def installation_token(self, installation_id: int) -> str:
        with self._lock:
            cached = self._tokens.get(installation_id)
            if cached and cached.expires_at - self._clock() > 300:
                return cached.value
            r = self._http.post(
                f"/app/installations/{installation_id}/access_tokens",
                headers=self._app_headers(),
                json={"permissions": self._permissions},
            )
            if r.status_code == 422:
                # The installation was granted fewer permissions than we ask for (e.g. an owner declined an update).
                # Ask for what the installation has, filtered to read-only.
                granted = self._granted(installation_id)
                r = self._http.post(
                    f"/app/installations/{installation_id}/access_tokens",
                    headers=self._app_headers(),
                    json={"permissions": granted},
                )
            r.raise_for_status()
            body = r.json()
            expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")).timestamp()
            self._tokens[installation_id] = _Token(body["token"], expires)
            return str(body["token"])

    def _granted(self, installation_id: int) -> dict[str, str]:
        r = self._http.get(f"/app/installations/{installation_id}", headers=self._app_headers())
        r.raise_for_status()
        perms = r.json().get("permissions") or {}
        return {k: "read" for k in self._permissions if k in perms}

    def token_provider(self, owner: str) -> Callable[[], str]:
        return lambda: self.installation_token(self.installation_id(owner))
