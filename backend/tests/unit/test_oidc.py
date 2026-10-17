# SPDX-License-Identifier: Apache-2.0
"""Token validation: every way an attacker could get a forged or misdirected token accepted."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aap.api.auth import safe_return_to
from aap.api.oidc import OidcClient, OidcError, OidcSettings, challenge_for, pkce_pair
from tests.oidc_idp import API_AUDIENCE, CLIENT_ID, CLIENT_SECRET, ISSUER, TENANT, FakeIdP


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def client(idp):
    s = OidcSettings(ISSUER, CLIENT_ID, "https://aap.test/auth/callback", API_AUDIENCE, TENANT)
    return OidcClient(s, client_secret=CLIENT_SECRET, http=idp.client())


def test_valid_id_token(idp, client):
    claims = client.validate_id_token(idp.id_token("n1"), "n1")
    assert claims["name"] == "Test User"


@pytest.mark.parametrize(
    "override,why",
    [
        ({"aud": "someone-else"}, "audience"),
        ({"iss": "https://evil.test/v2.0"}, "issuer"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"nbf": int(time.time()) + 3600}, "not yet valid"),
        ({"tid": "22222222-2222-2222-2222-222222222222"}, "tenant"),
    ],
)
def test_rejections(idp, client, override, why):
    with pytest.raises(OidcError):
        client.validate_id_token(idp.id_token("n1", **override), "n1")


def test_nonce_mismatch(idp, client):
    with pytest.raises(OidcError, match="nonce"):
        client.validate_id_token(idp.id_token("n1"), "n2")


def test_foreign_key_and_alg_confusion(idp, client):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = idp.sign(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "x",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "nonce": "n",
            "tid": TENANT,
        },
        key=other,
    )
    with pytest.raises(OidcError):
        client.validate_id_token(forged, "n")
    hs = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "x", "iat": 1, "exp": 2**31, "nonce": "n"},
        "k" * 32,
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(OidcError):
        client.validate_id_token(hs, "n")
    unsigned = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "x", "nonce": "n"}, None, algorithm="none", headers={"kid": "k1"}
    )
    with pytest.raises(OidcError):
        client.validate_id_token(unsigned, "n")


def test_key_rotation_refreshes_jwks_once(idp, client):
    client.validate_id_token(idp.id_token("n"), "n")  # caches k1
    idp.keys["k2"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.active_kid = "k2"
    assert client.validate_id_token(idp.id_token("n"), "n")["iss"] == ISSUER


def test_access_token_audience_is_the_api_not_the_web_client(idp, client):
    assert client.validate_access_token(idp.access_token())["roles"] == ["Reports.Read"]
    with pytest.raises(OidcError):
        client.validate_access_token(idp.access_token(aud=CLIENT_ID))


def test_discovery_issuer_mismatch_refused(idp):
    s = OidcSettings("https://idp.test/other/v2.0", CLIENT_ID, "https://aap.test/cb")
    import httpx

    def handler(request):
        return httpx.Response(200, json={"issuer": ISSUER})

    c = OidcClient(s, client_secret="x", http=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(OidcError, match="issuer"):
        c.metadata()


def test_client_needs_credentials():
    with pytest.raises(OidcError):
        OidcClient(OidcSettings(ISSUER, CLIENT_ID, "https://x/cb"))


def test_client_assertion_replaces_secret(idp):
    s = OidcSettings(ISSUER, CLIENT_ID, "https://aap.test/auth/callback")
    c = OidcClient(s, client_assertion=lambda: "mi-token", http=idp.client())
    url = c.authorization_url("st", "no", challenge_for("v"))
    redirect = idp.authorize(url)
    code = redirect.split("code=")[1].split("&")[0]
    with pytest.raises(OidcError):  # FakeIdP only accepts the secret, but we can see what was sent
        c.exchange_code(code, "v")
    sent = idp.token_requests[-1]
    assert sent["client_assertion"] == ["mi-token"] and "client_secret" not in sent
    assert sent["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]


def test_pkce_is_s256():
    v, c = pkce_pair()
    assert len(v) >= 43 and c == challenge_for(v) and "=" not in c


@pytest.mark.parametrize(
    "value,expected",
    [
        ("/applications/1", "/applications/1"),
        ("https://evil.test/", "/"),
        ("//evil.test", "/"),
        ("/\\evil.test", "/"),
        ("", "/"),
        (None, "/"),
        ("/ok\nSet-Cookie: x", "/"),
    ],
)
def test_return_to_is_same_origin_only(value, expected):
    assert safe_return_to(value) == expected
