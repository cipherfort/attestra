# SPDX-License-Identifier: Apache-2.0
"""`aap bootstrap <integration>`: set up each external system from nothing (ADR-031).

Every command is idempotent where the target allows it, prints no secret, never takes a secret on the command line
(prompts, or reads a named environment variable), and writes credentials only to the secret store
(Key Vault when AAP_SECRETS_BACKEND=keyvault; the 0600 dev store otherwise). Each prints the non-secret settings to
put in the deployment (Terraform variables or the local .env) and the next human step, if any.
"""

from __future__ import annotations

import getpass
import html
import json
import os
import secrets
import subprocess
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from aap.config import repo_root
from aap.connectors.github_app import TOKEN_PERMISSIONS
from aap.secrets import SecretStore, secret_store

# GitHub App manifest: read-only, the events the receiver handles. Repository + organization permissions.
APP_PERMISSIONS = {k: "read" for k in TOKEN_PERMISSIONS}
APP_EVENTS = ["workflow_run", "repository", "secret_scanning_alert", "code_scanning_alert", "dependabot_alert"]


def _secret_from(env_var: str | None, prompt: str) -> str:
    if env_var:
        value = os.environ.get(env_var)
        if not value:
            raise SystemExit(f"{env_var} is empty")
        return value
    return getpass.getpass(prompt)


def _say(msg: str) -> None:
    print(msg, flush=True)


# ------------------------------------------------------------------------------------------ GitHub App


def github_manifest(
    org: str, name: str, public_url: str | None, redirect: str, with_issues: bool = False
) -> dict[str, Any]:
    hook = (
        {"url": f"{public_url.rstrip('/')}/github/webhook", "active": True}
        if public_url
        else {"url": "https://example.invalid/disabled", "active": False}
    )  # local: no public receiver, polling only
    return {
        "name": name,
        "url": public_url or "https://github.com",
        "description": "Attestra (read-only): collects verified security evidence.",
        "hook_attributes": hook,
        "redirect_url": redirect,
        "public": False,
        "default_permissions": {**APP_PERMISSIONS, **({"issues": "write"} if with_issues else {})},
        "default_events": APP_EVENTS if public_url else [],
        "request_oauth_on_install": False,
    }


def github_app(
    org: str,
    name: str,
    public_url: str | None,
    host: str = "github.com",
    port: int = 8765,
    open_browser: bool = True,
    store: SecretStore | None = None,
    exchange: Callable[[str], dict[str, Any]] | None = None,
    with_issues: bool = False,
) -> dict[str, str]:
    """Manifest flow. The only manual step: an organisation owner clicks "Create GitHub App" (GitHub offers no API
    to create an App without that confirmation), then installs it on the chosen repositories."""
    store = store or secret_store()
    state = secrets.token_urlsafe(24)
    redirect = f"http://127.0.0.1:{port}/callback"
    manifest = github_manifest(org, name, public_url, redirect, with_issues)
    action = f"https://{host}/organizations/{org}/settings/apps/new?state={state}"
    result: dict[str, str] = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:  # keep the code out of logs
            pass

        def do_GET(self) -> None:
            u = urlparse(self.path)
            if u.path == "/":
                page = (
                    f'<form id="f" method="post" action="{html.escape(action)}">'
                    f'<input type="hidden" name="manifest" value="{html.escape(json.dumps(manifest))}">'
                    "<p>Creating Attestra GitHub App…</p><button>Continue</button></form>"
                    "<script>document.getElementById('f').submit()</script>"
                )
                self._send(200, page)
            elif u.path == "/callback":
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if not secrets.compare_digest(q.get("state", ""), state) or "code" not in q:
                    self._send(400, "state mismatch: start again")
                    return
                result["code"] = q["code"]
                self._send(200, "GitHub App created. You can close this tab and return to the terminal.")
                done.set()
            else:
                self._send(404, "")

        def _send(self, code: int, body: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body.encode())

    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _say(f"Open http://127.0.0.1:{port}/ as an owner of '{org}' and confirm 'Create GitHub App'.")
    if open_browser:
        webbrowser.open(f"http://127.0.0.1:{port}/")
    if not done.wait(timeout=900):
        server.shutdown()
        raise SystemExit("timed out waiting for GitHub (15 minutes)")
    server.shutdown()

    def default_exchange(code: str) -> dict[str, Any]:
        api = "https://api.github.com" if host == "github.com" else f"https://{host}/api/v3"
        r = httpx.post(f"{api}/app-manifests/{code}/conversions", headers={"Accept": "application/vnd.github+json"})
        r.raise_for_status()
        return dict(r.json())

    app = (exchange or default_exchange)(result["code"])
    store.put("github-app-private-key", app["pem"], "application/x-pem-file")
    store.put("github-webhook-secret", app["webhook_secret"])
    store.put("github-app-client-secret", app["client_secret"])  # unused today (no user OAuth); kept for rotation
    out = {
        "AAP_GITHUB_APP_CLIENT_ID": app["client_id"],
        "AAP_GITHUB_APP_ID": str(app["id"]),
        "AAP_GITHUB_ORG": org,
        "install_url": f"https://{host}/apps/{app['slug']}/installations/new",
    }
    _say("Stored github-app-private-key, github-webhook-secret in " + store.describe())
    _say(
        "Production: import the key into Key Vault as a non-exportable key and delete the secret:\n"
        "  aap bootstrap github-app-key-to-keyvault  (see docs/operations/integration-bootstrap.md)"
    )
    return out


# ------------------------------------------------------------------------------------------ others


def dependency_track(url: str, store: SecretStore | None = None) -> dict[str, str]:
    from aap.connectors.dependency_track import bootstrap

    store = store or secret_store()
    password = store.get("dependency-track-admin-password") or secrets.token_urlsafe(24)
    creds = bootstrap(url, password)
    store.put("dependency-track-admin-password", password)  # break-glass; rotate after handover
    store.put("dependency-track-api-key", creds["api_key"])
    _say(f"Dependency-Track: admin password rotated, team aap-platform key stored in {store.describe()}.")
    _say("NVD mirroring needs an API key (free, https://nvd.nist.gov/developers/request-an-api-key); OSV is enabled.")
    return {"AAP_DT_URL": url}


def defectdojo(url: str, admin_password_env: str | None, store: SecretStore | None = None) -> dict[str, str]:
    from aap.connectors.defectdojo import bootstrap

    store = store or secret_store()
    admin = _secret_from(admin_password_env, "DefectDojo admin password: ")
    creds = bootstrap(url, "admin", admin, store.get("defectdojo-service-password"))
    store.put("defectdojo-service-password", creds["service_password"])
    store.put("defectdojo-api-token", creds["api_token"])
    _say(f"DefectDojo: service user aap-platform scoped to one organization; token stored in {store.describe()}.")
    return {"AAP_DD_URL": url}


def jira(
    url: str, email: str, token_env: str | None, create_project: str | None, store: SecretStore | None = None
) -> dict[str, str]:
    from aap.connectors.jira import JiraClient, JiraError

    store = store or secret_store()
    token = _secret_from(token_env, "Jira API token (https://id.atlassian.com/manage-profile/security/api-tokens): ")
    client = JiraClient(url, email=email, api_token=token)
    me = client.myself()
    _say(f"Jira: authenticated as {me.get('displayName')}.")
    if create_project:
        try:
            client.project(create_project)
            _say(f"Project {create_project} exists.")
        except JiraError:
            client.create_project(create_project, "Application Security", me["accountId"])
            _say(f"Created project {create_project}. Set jira.default_project in config/integrations.yaml (PR).")
    store.put("jira-api-token", token)
    return {"AAP_JIRA_URL": url, "AAP_JIRA_EMAIL": email}


def gitlab(
    url: str,
    group: str,
    admin_token_env: str | None,
    public_url: str | None = None,
    store: SecretStore | None = None,
    with_issues: bool = False,
) -> dict[str, str]:
    """GitLab from nothing (ADR-033): a group access token for the platform (Reporter; read_api + read_repository,
    one year), and a group webhook for job and push events when the tier has group webhooks (Premium). The admin
    token is used for these two calls only and is never stored."""
    import secrets as pysecrets
    from datetime import date, timedelta

    import httpx

    store = store or secret_store()
    admin = _secret_from(admin_token_env, "GitLab token of a group Owner (scope: api), used once and not stored: ")
    gl = httpx.Client(base_url=f"{url.rstrip('/')}/api/v4", headers={"PRIVATE-TOKEN": admin}, timeout=30)
    g = gl.get(f"/groups/{group.replace('/', '%2F')}")
    if g.status_code != 200:
        raise SystemExit(f"group {group!r} not found or not visible to that token (HTTP {g.status_code})")
    gid = g.json()["id"]
    r = gl.post(
        f"/groups/{gid}/access_tokens",
        json={
            "name": "appsec-assurance-platform",
            "scopes": ["read_api", "read_repository"],
            "access_level": 20,
            "expires_at": (date.today() + timedelta(days=364)).isoformat(),
        },
    )
    if r.status_code >= 300:
        raise SystemExit(f"could not create the group access token (HTTP {r.status_code}): {r.text[:200]}")
    store.put("gitlab-token", r.json()["token"])
    _say("Group access token created (Reporter; read_api, read_repository; expires in a year) and stored.")
    out = {"AAP_GITLAB_URL": url.rstrip("/"), "AAP_GITLAB_GROUP": group}
    if with_issues:  # a second, write-capable token kept apart from the read-only one (ADR-018: only writer of issues)
        r = gl.post(
            f"/groups/{gid}/access_tokens",
            json={
                "name": "appsec-assurance-platform-issues",
                "scopes": ["api"],
                "access_level": 20,
                "expires_at": (date.today() + timedelta(days=364)).isoformat(),
            },
        )
        if r.status_code >= 300:
            raise SystemExit(f"could not create the issues token (HTTP {r.status_code}): {r.text[:200]}")
        store.put("gitlab-issues-token", r.json()["token"])
        _say("Issues token created (Reporter; api: can open and comment on issues, cannot push code) and stored.")
    if public_url:
        hook_secret = pysecrets.token_urlsafe(32)
        h = gl.post(
            f"/groups/{gid}/hooks",
            json={
                "url": f"{public_url.rstrip('/')}/gitlab/webhook",
                "token": hook_secret,
                "job_events": True,
                "push_events": True,
                "merge_requests_events": True,
                "enable_ssl_verification": True,
            },
        )
        if h.status_code < 300:
            store.put("gitlab-webhook-secret", hook_secret)
            _say("Group webhook created (job, push and merge request events).")
        else:
            _say(
                f"Group webhooks are not available here (HTTP {h.status_code}; GitLab Premium feature). The platform "
                "polls finished component jobs on its schedule instead (gitlab.settings_sync_interval)."
            )
    else:
        _say("No --public-url: no webhook. The platform polls finished component jobs on its schedule.")
    return out


def oidc_dev(store: SecretStore | None = None) -> dict[str, str]:
    """Local mock IdP (deploy/local/oidc.json) accepts any secret; production uses the managed identity instead."""
    store = store or secret_store()
    if os.environ.get("AAP_ENV") == "production":
        raise SystemExit("oidc-dev is for the local mock identity provider only")
    store.put("oidc-client-secret", secrets.token_urlsafe(24))
    return {
        "AAP_OIDC_ISSUER": "http://localhost:8090/aap",
        "AAP_OIDC_CLIENT_ID": "aap-web",
        "AAP_OIDC_TENANT_ID": "00000000-0000-4000-8000-00000000000a",
        "AAP_PUBLIC_URL": "http://localhost:8765",
    }


def trust_root() -> dict[str, str]:
    """Sigstore trust roots (public-good + GitHub) for attestation verification. Public data, committed to config/."""
    out = repo_root() / "config" / "sigstore" / "trusted_root.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    data = subprocess.run(["gh", "attestation", "trusted-root"], check=True, capture_output=True, timeout=120).stdout  # noqa: S607
    out.write_bytes(data)
    _say(f"Wrote {out.relative_to(repo_root())} ({len(data.splitlines())} trust roots). Commit it via PR.")
    return {}


def github_app_key_to_keyvault(key_name: str = "github-app-key") -> dict[str, str]:
    """Move the GitHub App private key from a Key Vault SECRET into a non-exportable, sign-only Key Vault KEY
    (HSM-protected on the premium vault), then delete the secret. Afterwards the worker signs App JWTs inside Key Vault
    (`AAP_GITHUB_APP_KEY_ID`) and the private key is never again readable by anyone, including administrators."""
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.secrets import SecretClient
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from aap.secrets import azure_credential

    vault = os.environ.get("AAP_KEYVAULT_URL")
    if os.environ.get("AAP_SECRETS_BACKEND") != "keyvault" or not vault:
        raise SystemExit("run with AAP_SECRETS_BACKEND=keyvault and AAP_KEYVAULT_URL set")
    cred = azure_credential()
    secrets_client = SecretClient(vault, cred)
    pem = secrets_client.get_secret("github-app-private-key").value or ""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SystemExit("not an RSA key")
    n = key.private_numbers()

    def b(i: int) -> bytes:
        return i.to_bytes((i.bit_length() + 7) // 8, "big")

    from azure.keyvault.keys import JsonWebKey, KeyType

    jwk = JsonWebKey(
        kty=KeyType.rsa_hsm,
        n=b(n.public_numbers.n),
        e=b(n.public_numbers.e),
        d=b(n.d),
        p=b(n.p),
        q=b(n.q),
        dp=b(n.dmp1),
        dq=b(n.dmq1),
        qi=b(n.iqmp),
        key_ops=["sign"],
    )
    imported = KeyClient(vault, cred).import_key(key_name, jwk, hardware_protected=True, exportable=False)
    secrets_client.begin_delete_secret("github-app-private-key").wait()
    _say("Imported as a non-exportable HSM key; deleted the secret (soft-deleted for the vault's retention period).")
    return {"AAP_GITHUB_APP_KEY_ID": str(imported.id)}
