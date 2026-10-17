# SPDX-License-Identifier: Apache-2.0
"""GitHub App token minting and settings summarisers, against recorded API shapes (respx)."""

import base64
import json

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aap.connectors.github_app import TOKEN_PERMISSIONS, GitHubAppAuth, PemSigner, app_jwt
from aap.connectors.github_settings import (
    GitHubRest,
    OwnerResolution,
    Unavailable,
    codeowners_coverage,
    collect_repository,
    parse_codeowners,
    summarise_application,
    summarise_environments,
    summarise_rules,
    summarise_security,
    summarise_threat_model,
)

API = "https://api.github.com"


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return k, pem


def test_app_jwt_is_rs256_with_github_time_bounds(key):
    k, pem = key
    token = app_jwt("Iv23abc", PemSigner(pem), now=1_000_000)
    claims = jwt.decode(token, k.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims == {"iat": 1_000_000 - 60, "exp": 1_000_000 + 540, "iss": "Iv23abc"}
    assert claims["exp"] - claims["iat"] <= 600


@respx.mock
def test_installation_token_requests_read_only_permissions_and_caches(key):
    k, pem = key
    now = [1_800_000_000.0]
    respx.get(f"{API}/orgs/acme/installation").respond(200, json={"id": 42})
    route = respx.post(f"{API}/app/installations/42/access_tokens").respond(
        201, json={"token": "ghs_x", "expires_at": "2027-01-15T09:00:00Z"}
    )
    auth = GitHubAppAuth("Iv23abc", PemSigner(pem), clock=lambda: now[0])
    provider = auth.token_provider("acme")
    assert provider() == "ghs_x" and provider() == "ghs_x"
    assert route.call_count == 1  # cached
    sent = json.loads(route.calls[0].request.content)
    assert set(sent["permissions"].values()) == {"read"} and sent["permissions"] == dict(TOKEN_PERMISSIONS)
    bearer = route.calls[0].request.headers["authorization"].split()[1]
    assert (
        jwt.decode(bearer, k.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})[
            "iss"
        ]
        == "Iv23abc"
    )
    # within 5 minutes of expiry → refreshed
    now[0] = 1_800_000_000.0 + 10**9  # far future
    route.respond(201, json={"token": "ghs_y", "expires_at": "2099-01-01T00:00:00Z"})
    assert provider() == "ghs_y"


@respx.mock
def test_not_installed_is_a_clear_error(key):
    _, pem = key
    respx.get(f"{API}/orgs/nobody/installation").respond(404)
    respx.get(f"{API}/users/nobody/installation").respond(404)
    with pytest.raises(LookupError, match="not installed"):
        GitHubAppAuth("Iv23abc", PemSigner(pem)).installation_id("nobody")


@respx.mock
def test_downgraded_installation_gets_read_only_subset(key):
    _, pem = key
    first = respx.post(f"{API}/app/installations/7/access_tokens")
    first.side_effect = [
        httpx.Response(422, json={"message": "permissions not granted"}),
        httpx.Response(201, json={"token": "ghs_z", "expires_at": "2099-01-01T00:00:00Z"}),
    ]
    respx.get(f"{API}/app/installations/7").respond(
        200, json={"permissions": {"metadata": "read", "contents": "write"}}
    )
    assert GitHubAppAuth("Iv23abc", PemSigner(pem)).installation_token(7) == "ghs_z"
    assert json.loads(first.calls[1].request.content)["permissions"] == {"metadata": "read", "contents": "read"}


# ---------------------------------------------------------------- summarisers


def test_rules_take_the_stronger_of_rulesets_and_classic_protection():
    rules = [
        {
            "type": "pull_request",
            "ruleset_id": 1,
            "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True},
        },
        {
            "type": "required_status_checks",
            "ruleset_id": 1,
            "parameters": {"required_status_checks": [{"context": "aap / sast"}]},
        },
        {"type": "non_fast_forward", "ruleset_id": 2},
    ]
    classic = {
        "required_pull_request_reviews": {"required_approving_review_count": 2},
        "required_status_checks": {"checks": [{"context": "aap / sca"}], "contexts": ["aap / sca"]},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": True},
    }
    s = summarise_rules(rules, classic)
    assert s["required_approvals"] == 2 and s["require_code_owner_review"] and s["requires_pr"]
    assert s["required_checks"] == ["aap / sast", "aap / sca"]
    assert s["blocks_force_push"] and not s["blocks_deletion"]


def test_no_rules_means_nothing_required():
    s = summarise_rules([], None)
    assert not s["requires_pr"] and s["required_approvals"] == 0 and not s["blocks_force_push"]


def test_security_settings_absent_is_unavailable_not_disabled():
    with pytest.raises(Unavailable):
        summarise_security({"id": 1})
    s = summarise_security(
        {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "disabled"},
            }
        }
    )
    assert s["features"] == {"secret_scanning": True, "secret_scanning_push_protection": False}


@pytest.mark.parametrize(
    "content,covered",
    [
        ("* @acme/team", [".github/workflows/", ".security/"]),
        ("/.github/workflows/ @acme/platform\n", [".github/workflows/"]),
        ("* @acme/team\n/.security/\n", [".github/workflows/"]),  # last match has no owner → uncovered
        ("docs/ @acme/docs", []),
        ("/.security/** @acme/appsec\n.github/ @acme/platform", [".github/workflows/", ".security/"]),
    ],
)
def test_codeowners_last_match_wins(content, covered):
    assert codeowners_coverage(parse_codeowners(content), [".github/workflows/", ".security/"]) == covered


def test_environments_find_production_and_static_cloud_secrets():
    envs = [
        {"name": "staging"},
        {
            "name": "Production",
            "deployment_branch_policy": {"protected_branches": True},
            "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "Team"}, {"type": "User"}]}],
        },
    ]
    s = summarise_environments(envs, ["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY"], {"Production": ["AZURE_CLIENT_SECRET"]})
    assert s["production"]["required_reviewers"] == 2 and s["production"]["branch_policy"]
    assert s["static_cloud_secret_names"] == ["AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET"]


def test_threat_model_unmitigated_high_threats():
    threats = {
        "threats": [
            {"id": "TM-01", "rating": "critical"},
            {"id": "TM-02", "rating": "high"},
            {"id": "TM-03", "rating": "high"},
            {"id": "TM-04", "rating": "low"},
        ]
    }
    mitigations = {"mitigations": [{"threat": "TM-01", "status": "verified"}, {"threat": "TM-02", "status": "planned"}]}
    residual = {"residual_risks": [{"threat": "TM-03", "exception_id": "EX-1"}]}
    s = summarise_threat_model(threats, mitigations, residual, [])
    assert s["high_threats"] == 3 and s["high_threats_unmitigated"] == ["TM-02"] and s["schema_valid"]


def test_application_summary_resolves_owners_and_asvs():
    doc = {
        "application": {
            "name": "Claims",
            "owners": {
                "business_owner": "jane@example.org",
                "technical_owner": "@acme/leads",
                "team": "@acme/ghost",
                "security_champion": "@ajones",
            },
            "security_contact": {"email": "sec@example.org"},
            "repositories": ["acme/claims-infra", "acme/unlinked"],
        }
    }
    owners = OwnerResolution({"ajones"}, {"jane@example.org"}, {"acme/leads"})
    s = summarise_application(
        doc, {"asvs_version": "5.0.0", "target_level": 2}, [], owners, True, {"acme/claims-infra"}, 3
    )
    assert s["unresolved_owners"] == ["team"] and s["unlinked_repos"] == 1 and s["champion"] == "@ajones"
    assert s["asvs_target_level"] == 2 and s["asvs_required_level"] == 3 and s["schema_valid"]


# ---------------------------------------------------------------- collection: a 403 skips that evidence type


@respx.mock
def test_collect_reports_gaps_instead_of_guessing():
    repo = "acme/claims"
    respx.get(f"{API}/repos/{repo}").respond(200, json={"id": 9, "default_branch": "main", "visibility": "private"})
    respx.get(f"{API}/repos/{repo}/commits/main").respond(200, json={"sha": "c" * 40})
    respx.get(f"{API}/repos/{repo}/rules/branches/main").respond(
        200, json=[{"type": "pull_request", "ruleset_id": 1, "parameters": {"required_approving_review_count": 2}}]
    )
    respx.get(f"{API}/repos/{repo}/branches/main/protection").respond(404)
    respx.get(url__regex=rf"{API}/repos/{repo}/contents/.*").respond(404)
    respx.get(f"{API}/orgs/acme/.github").respond(404)
    respx.get(url__regex=rf"{API}/repos/acme/.github/contents/.*").respond(404)
    respx.get(url__regex=rf"{API}/repos/{repo}/collaborators.*").respond(200, json=[])
    respx.get(f"{API}/repos/{repo}/environments").respond(403)  # permission not granted
    respx.get(f"{API}/repos/{repo}/actions/permissions").respond(
        200, json={"enabled": True, "allowed_actions": "selected"}
    )
    respx.get(f"{API}/repos/{repo}/actions/permissions/workflow").respond(
        200, json={"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
    )
    respx.get(url__regex=rf"{API}/repos/{repo}/secret-scanning/alerts.*").respond(
        200, json=[{"number": 3, "validity": "active", "secret_type": "azure_ad_client_secret"}]
    )
    snap = collect_repository(GitHubRest(lambda: "t"), repo)
    assert snap.head_sha == "c" * 40
    assert snap.evidence["repo.ruleset"]["required_approvals"] == 2
    assert snap.evidence["repo.codeowners"] == {"present": False, "errors": 0, "covered_paths": []}
    assert snap.evidence["scan.secrets"]["active"] == 1
    assert "repo.environments" not in snap.evidence and "403" in snap.gaps["repo.environments"]
    assert "repo.security_settings" in snap.gaps  # security_and_analysis not visible
    assert snap.documents["SECURITY.md"] is False


def test_token_is_never_in_urls():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    api = GitHubRest(lambda: "ghs_secret", http=httpx.Client(base_url=API, transport=httpx.MockTransport(handler)))
    api.get("/repos/a/b")
    assert all("ghs_secret" not in u for u in seen)


def test_b64_helper_roundtrip():
    # guard for the JWT encoder: no padding, url-safe alphabet
    from aap.connectors.github_app import _b64url

    assert "=" not in _b64url(b"\xff\xfe") and base64.urlsafe_b64decode(_b64url(b"ab") + "==") == b"ab"
