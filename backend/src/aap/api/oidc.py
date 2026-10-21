# SPDX-License-Identifier: Apache-2.0
"""OpenID Connect client for the BFF (ADR-014). Written against the standard, configured for Entra ID.

* Authorization code + PKCE (S256), `state` and `nonce`, confidential client.
* Client authentication: a client secret (local mock IdP only) or a **client assertion** — in Azure, the platform's
  managed identity token for `api://AzureADTokenExchange` presented as a federated credential of the app registration,
  so no client secret exists anywhere (examples/terraform/azure/modules/entra).
* ID tokens and API access tokens validated locally against the issuer's JWKS: signature (RS256 only), `iss`, `aud`,
  `exp`/`nbf`/`iat` with 60 s leeway, `nonce`, and the tenant when one is pinned.

Tested against an in-process IdP (unit) and a real OIDC server container (integration, `-m oidc`).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

LEEWAY = 60
CACHE_SECONDS = 3600


class OidcError(Exception):
    """Authentication failed. The message is safe to log; it never contains tokens."""


def challenge_for(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    return verifier, challenge_for(verifier)


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    client_id: str
    redirect_uri: str
    api_audience: str | None = None  # accepted `aud` for bearer tokens (service clients)
    tenant_id: str | None = None  # pin `tid` (Entra)
    scopes: str = "openid profile email"
    post_logout_redirect_uri: str | None = None
    # Back-channel origin when the platform cannot reach the issuer's public host (Docker Compose, Kubernetes: the
    # browser uses http://localhost:8180, the API container http://keycloak:8180). Only server-to-server calls
    # (discovery, keys, token) are rewritten; the issuer is still checked exactly.
    internal_url: str | None = None


class OidcClient:
    def __init__(
        self,
        settings: OidcSettings,
        *,
        client_secret: str | None = None,
        client_assertion: Callable[[], str] | None = None,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not client_secret and not client_assertion:
            raise OidcError("an OIDC client needs a client secret or a client assertion provider")
        self.s = settings
        self._secret = client_secret
        self._assertion = client_assertion
        self._http = http or httpx.Client(timeout=15.0, follow_redirects=False)
        self._clock = clock
        self._meta: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, jwt.PyJWKSet] | None = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- discovery

    def _backchannel(self, url: str) -> str:
        if not self.s.internal_url:
            return url
        from urllib.parse import urlsplit, urlunsplit

        public, target, internal = urlsplit(self.s.issuer), urlsplit(url), urlsplit(self.s.internal_url)
        if (target.scheme, target.netloc) != (public.scheme, public.netloc):
            return url  # not the issuer's host: leave it alone
        return urlunsplit((internal.scheme, internal.netloc, target.path, target.query, target.fragment))

    def metadata(self) -> dict[str, Any]:
        with self._lock:
            if self._meta and self._clock() - self._meta[0] < CACHE_SECONDS:
                return self._meta[1]
            url = self._backchannel(self.s.issuer.rstrip("/") + "/.well-known/openid-configuration")
            r = self._http.get(url)
            r.raise_for_status()
            meta = r.json()
            if meta.get("issuer") != self.s.issuer:  # single-tenant only: no /common, no issuer templates
                raise OidcError(f"discovery issuer {meta.get('issuer')!r} does not match the configured issuer")
            self._meta = (self._clock(), meta)
            return dict(meta)

    def _keys(self, refresh: bool = False) -> jwt.PyJWKSet:
        if self._jwks and not refresh and self._clock() - self._jwks[0] < CACHE_SECONDS:
            return self._jwks[1]
        r = self._http.get(self._backchannel(self.metadata()["jwks_uri"]))
        r.raise_for_status()
        self._jwks = (self._clock(), jwt.PyJWKSet.from_dict(r.json()))
        return self._jwks[1]

    def _key_for(self, token: str) -> Any:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as e:
            raise OidcError("malformed token header") from e
        for refresh in (False, True):  # an unknown kid triggers one JWKS refresh (key rotation)
            for k in self._keys(refresh).keys:
                if k.key_id == kid:
                    return k.key
        raise OidcError("signing key not found in issuer JWKS")

    # ---------------------------------------------------------------- authorization code flow

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        q = {
            "client_id": self.s.client_id,
            "response_type": "code",
            "redirect_uri": self.s.redirect_uri,
            "scope": self.s.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_mode": "query",
        }
        return f"{self.metadata()['authorization_endpoint']}?{urlencode(q)}"

    def _client_auth(self) -> dict[str, str]:
        if self._assertion is not None:
            return {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self._assertion(),
            }
        return {"client_secret": self._secret or ""}

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        r = self._http.post(
            self._backchannel(self.metadata()["token_endpoint"]),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.s.redirect_uri,
                "client_id": self.s.client_id,
                "code_verifier": code_verifier,
                **self._client_auth(),
            },
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            err = (
                r.json().get("error", "error")
                if r.headers.get("content-type", "").startswith("application/json")
                else ""
            )
            raise OidcError(f"token endpoint refused the code ({r.status_code} {err})")
        return dict(r.json())

    # ---------------------------------------------------------------- validation

    def _decode(self, token: str, audience: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self._key_for(token),
                algorithms=["RS256"],
                audience=audience,
                issuer=self.metadata()["issuer"],
                leeway=LEEWAY,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise OidcError(f"token rejected: {type(e).__name__}") from e
        if self.s.tenant_id and claims.get("tid") != self.s.tenant_id:
            raise OidcError("token issued for another tenant")
        return dict(claims)

    def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        claims = self._decode(id_token, self.s.client_id)
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("nonce mismatch")
        return claims

    def validate_access_token(self, token: str) -> dict[str, Any]:
        if not self.s.api_audience:
            raise OidcError("bearer tokens are not accepted (no API audience configured)")
        return self._decode(token, self.s.api_audience)

    def end_session_url(self) -> str | None:
        end = self.metadata().get("end_session_endpoint")
        if not end:
            return None
        # OpenID Connect RP-Initiated Logout: with a post-logout redirect, the provider must know which client asks
        # (id_token_hint or client_id). Without either, Keycloak refuses ("Missing parameters: id_token_hint") and
        # keeps its own session, so the next visit signs the person straight back in.
        params = {"client_id": self.s.client_id}
        if self.s.post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = self.s.post_logout_redirect_uri
        return f"{end}?{urlencode(params)}"


def managed_identity_assertion(client_id: str) -> Callable[[], str]:
    """Federated credential: the user-assigned managed identity's token, audience api://AzureADTokenExchange."""
    from azure.identity import ManagedIdentityCredential

    cred = ManagedIdentityCredential(client_id=client_id)
    return lambda: cred.get_token("api://AzureADTokenExchange/.default").token
