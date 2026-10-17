# SPDX-License-Identifier: Apache-2.0
"""DefectDojo client (ADR-018 role: optional triage workbench). Written and tested against DefectDojo 3.4.0.

The platform forwards verified scan evidence (SARIF, ZAP XML, ...) so AppSec engineers can triage in DefectDojo's
UI. DefectDojo is never a ticket writer (Jira push disabled) and never the source of truth for finding state:
closure stays evidence-based in the platform.

Access model (DefectDojo 3.x OSS has no role/membership API; it uses `authorized_users` on organizations):
bootstrap creates ONE organization, "Attestra", authorizes only the `aap-platform` service user on
it, and every application becomes an asset (product) inside it. The service user is not staff, not superuser, and
has no configuration permissions, so it cannot reach anything outside that organization.
"""

from __future__ import annotations

import secrets
from typing import Any

import httpx

ORGANIZATION = "Attestra"
SERVICE_USER = "aap-platform"
SCAN_TYPES = {"application/sarif+json": "SARIF"}


class DefectDojoError(Exception):
    pass


class DefectDojoClient:
    def __init__(self, base_url: str, api_token: str, http: httpx.Client | None = None, timeout: float = 120.0):
        self.base = base_url.rstrip("/") + "/api/v2"
        self._h = {"Authorization": f"Token {api_token}", "Accept": "application/json"}
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)

    def reimport(
        self, *, scan_type: str, data: bytes, filename: str, product: str, engagement: str, test_title: str
    ) -> dict[str, Any]:
        """Idempotent: the same test is updated on every run, findings no longer reported are closed in DD."""
        r = self._http.post(
            f"{self.base}/reimport-scan/",
            headers=self._h,
            data={
                "scan_type": scan_type,
                "auto_create_context": "true",
                "product_type_name": ORGANIZATION,
                "product_name": product,
                "engagement_name": engagement,
                "test_title": test_title,
                "close_old_findings": "true",
                "deduplication_on_engagement": "true",
                "push_to_jira": "false",
            },
            files={"file": (filename, data)},
        )
        if r.status_code not in (200, 201):
            raise DefectDojoError(f"reimport {test_title!r} → {r.status_code}: {r.text[:200]}")
        return dict(r.json())

    def findings(self, test_id: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        url: str | None = f"{self.base}/findings/?test={test_id}&limit=200"
        while url:
            r = self._http.get(url, headers=self._h)
            r.raise_for_status()
            d = r.json()
            out += d["results"]
            url = d.get("next")
        return out


def bootstrap(
    base_url: str,
    admin_user: str,
    admin_password: str,
    service_password: str | None = None,
    http: httpx.Client | None = None,
) -> dict[str, str]:
    """First-run setup of a fresh DefectDojo (admin credentials come from its initializer; see deploy/).

    Creates the service user (random password) and the platform organization authorized for that user only, and
    returns the user's API token plus its password. DefectDojo refuses password changes through its API, so a re-run
    needs the stored `service_password`; if it is lost, reset it on the server
    (`python manage.py changepassword aap-platform`) and pass the new one."""
    h = http or httpx.Client(timeout=60.0)
    api = base_url.rstrip("/") + "/api/v2"
    try:
        r = h.post(f"{api}/api-token-auth/", json={"username": admin_user, "password": admin_password})
        if r.status_code != 200:
            raise DefectDojoError("admin login failed")
        adm = {"Authorization": f"Token {r.json()['token']}"}
        users = h.get(f"{api}/users/", headers=adm, params={"username": SERVICE_USER}).json()["results"]
        profile = {"is_active": True, "is_superuser": False, "is_staff": False, "configuration_permissions": []}
        if users:
            if not service_password:
                raise DefectDojoError(
                    f"{SERVICE_USER} already exists; pass its stored password (secret defectdojo-service-password) or "
                    "reset it with `python manage.py changepassword aap-platform`"
                )
            uid = users[0]["id"]
            h.patch(f"{api}/users/{uid}/", headers=adm, json=profile).raise_for_status()  # re-assert least privilege
            password = service_password
        else:
            password = secrets.token_urlsafe(32)
            r = h.post(
                f"{api}/users/",
                headers=adm,
                json={"username": SERVICE_USER, "password": password, "email": "aap-platform@localhost", **profile},
            )
            r.raise_for_status()
            uid = r.json()["id"]
        # least privilege, re-asserted on every run: authorized on the platform organization and nowhere else
        url: str | None = f"{api}/organizations/?limit=200"
        while url:
            page = h.get(url, headers=adm).json()
            for o in page["results"]:
                if o["name"] != ORGANIZATION and uid in (o.get("authorized_users") or []):
                    keep = [u for u in o["authorized_users"] if u != uid]
                    h.patch(
                        f"{api}/organizations/{o['id']}/", headers=adm, json={"authorized_users": keep}
                    ).raise_for_status()
            url = page.get("next")
        orgs = h.get(f"{api}/organizations/", headers=adm, params={"name": ORGANIZATION}).json()["results"]
        if orgs:
            h.patch(
                f"{api}/organizations/{orgs[0]['id']}/", headers=adm, json={"authorized_users": [uid]}
            ).raise_for_status()
        else:
            h.post(
                f"{api}/organizations/", headers=adm, json={"name": ORGANIZATION, "authorized_users": [uid]}
            ).raise_for_status()
        r = h.post(f"{api}/api-token-auth/", json={"username": SERVICE_USER, "password": password})
        if r.status_code != 200:
            raise DefectDojoError(f"{SERVICE_USER} login failed: the stored password is wrong")
        return {"api_token": r.json()["token"], "user_id": str(uid), "service_password": password}
    except httpx.HTTPError as e:
        raise DefectDojoError(f"DefectDojo unreachable or failed: {type(e).__name__}") from e
