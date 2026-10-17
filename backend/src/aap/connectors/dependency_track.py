# SPDX-License-Identifier: Apache-2.0
"""OWASP Dependency-Track client (ADR-009). Written and tested against Dependency-Track 4.14.5 (real container).

Role: continuous re-analysis of every current SBOM against NVD/OSV/GHSA as new advisories appear. The platform stays
the system of record: DT findings become platform vulnerabilities, component matches and dependency findings with
contextual priority; DT's own analysis state (suppression, audit) is not imported as truth.

Projects are named `<app_key>/<owner>/<repo>`, version = the scanned branch. The platform's API key belongs to the
team `aap-platform` with BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO, VIEW_VULNERABILITY only (bootstrap).
"""

from __future__ import annotations

import base64
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

PLATFORM_TEAM = "aap-platform"
PLATFORM_PERMISSIONS = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


class DependencyTrackError(Exception):
    pass


class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str, http: httpx.Client | None = None, timeout: float = 60.0):
        self.base = base_url.rstrip("/")
        self._h = {"X-Api-Key": api_key, "Accept": "application/json"}
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)

    def _req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        r = self._http.request(method, self.base + path, headers=self._h, **kw)
        if r.status_code in (401, 403):
            raise DependencyTrackError(
                f"{method} {path.split('?')[0]} refused ({r.status_code}): check the team's permissions"
            )
        return r

    def version(self) -> str:
        return str(self._req("GET", "/api/version").json()["version"])

    def upload_bom(self, project: str, version: str, bom: bytes) -> str:
        body = {
            "projectName": project,
            "projectVersion": version,
            "autoCreate": True,
            "bom": base64.b64encode(bom).decode(),
        }
        r = self._req("PUT", "/api/v1/bom", json=body)
        if r.status_code != 200:
            raise DependencyTrackError(f"BOM upload failed ({r.status_code}): {r.text[:200]}")
        return str(r.json()["token"])

    def wait(
        self, token: str, timeout: float = 300.0, poll: float = 2.0, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._req("GET", f"/api/v1/event/token/{token}").json().get("processing", True):
                return
            sleep(poll)
        raise DependencyTrackError(f"BOM processing did not finish within {timeout:.0f}s")

    def project(self, name: str, version: str) -> dict[str, Any] | None:
        r = self._req("GET", "/api/v1/project/lookup", params={"name": name, "version": version})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return dict(r.json())

    def findings(self, project_uuid: str) -> list[dict[str, Any]]:
        r = self._req("GET", f"/api/v1/finding/project/{project_uuid}", params={"suppressed": "false"})
        r.raise_for_status()
        return list(r.json())


def to_advisory(finding: Mapping[str, Any]) -> dict[str, Any]:
    """One DT finding → the platform's advisory shape (supply_chain.upsert_vulnerability / link_exact).

    Key: the CVE when the advisory names exactly one (aliases from DT, else NVD links in references), otherwise DT's
    vulnId. Absent fields (EPSS, KEV) are left absent so they never overwrite values from the authoritative feeds."""
    v, c = finding["vulnerability"], finding["component"]
    ids = {v["vulnId"]}
    for a in v.get("aliases") or []:
        ids |= {x for k, x in a.items() if k.endswith("Id") and isinstance(x, str)}
    cves = sorted({i for i in ids if i.startswith("CVE-")} | set(CVE.findall(v.get("references") or "")))
    key = cves[0] if len(cves) == 1 else v["vulnId"]
    adv: dict[str, Any] = {
        "id": key,
        "aliases": sorted((ids | set(cves)) - {key}),
        "source": "dependency-track",
        "title": (v.get("title") or v.get("description") or "")[:300],
        "cwe": [w["cweId"] for w in v.get("cwes") or [] if "cweId" in w] or ([v["cweId"]] if v.get("cweId") else []),
        "cvss_v3_score": v.get("cvssV3BaseScore"),
        "cvss_v3_vector": v.get("cvssV3Vector"),
        "affected": [{"purl": c["purl"].split("@", 1)[0], "versions": [c["version"]]}] if c.get("purl") else [],
        "dt": {
            "vuln_uuid": v["uuid"],
            "component_uuid": c["uuid"],
            "analyzer": (finding.get("attribution") or {}).get("analyzerIdentity"),
        },
    }
    if v.get("epssScore") is not None:
        adv |= {"epss_score": v["epssScore"], "epss_percentile": v.get("epssPercentile")}
    return adv


# ------------------------------------------------------------------------------------------ bootstrap (admin, once)


def bootstrap(
    base_url: str,
    admin_password: str,
    initial_password: str = "admin",  # noqa: S107 - DT's documented first-run default, changed here
    http: httpx.Client | None = None,
    osv_ecosystems: str = "Maven;npm;PyPI;Go;NuGet;crates.io;RubyGems;Packagist",
) -> dict[str, str]:
    """First-run setup of a fresh Dependency-Track. Idempotent apart from minting a new key on each run.

    1. Force-change the default `admin/admin` password (no-op if already changed).
    2. Log in as admin; create team `aap-platform` with least-privilege permissions.
    3. Mint an API key for the team (shown once by DT ≥ 4.13: the caller must store it immediately).
    4. Enable OSV (alias sync on). NVD needs an API key: see docs/operations/integration-bootstrap.md.
    """
    try:
        return _bootstrap(
            base_url.rstrip("/"), admin_password, initial_password, http or httpx.Client(timeout=60.0), osv_ecosystems
        )
    except httpx.HTTPError as e:
        raise DependencyTrackError(f"Dependency-Track unreachable or failed: {type(e).__name__}") from e


def _bootstrap(
    base: str, admin_password: str, initial_password: str, h: httpx.Client, osv_ecosystems: str
) -> dict[str, str]:
    r = h.post(
        f"{base}/api/v1/user/forceChangePassword",
        data={
            "username": "admin",
            "password": initial_password,
            "newPassword": admin_password,
            "confirmPassword": admin_password,
        },
    )
    if r.status_code not in (200, 401):  # 401: the initial password no longer works (already changed)
        raise DependencyTrackError(f"password change failed ({r.status_code}): {r.text[:200]}")
    r = h.post(f"{base}/api/v1/user/login", data={"username": "admin", "password": admin_password})
    if r.status_code != 200:
        raise DependencyTrackError("admin login failed: wrong password, or the account is locked")
    auth = {"Authorization": f"Bearer {r.text.strip()}"}
    teams = h.get(f"{base}/api/v1/team", headers=auth).json()
    team = next((t for t in teams if t["name"] == PLATFORM_TEAM), None)
    if team is None:
        team = h.put(f"{base}/api/v1/team", headers=auth, json={"name": PLATFORM_TEAM}).json()
    have = {p["name"] for p in team.get("permissions") or []}
    for perm in PLATFORM_PERMISSIONS:
        if perm not in have:
            h.post(f"{base}/api/v1/permission/{perm}/team/{team['uuid']}", headers=auth).raise_for_status()
    key = h.put(f"{base}/api/v1/team/{team['uuid']}/key", headers=auth)
    key.raise_for_status()
    for prop, value in (
        ("google.osv.enabled", osv_ecosystems),
        ("google.osv.alias.sync.enabled", "true"),
    ):
        h.post(
            f"{base}/api/v1/configProperty",
            headers=auth,
            json={"groupName": "vuln-source", "propertyName": prop, "propertyValue": value},
        ).raise_for_status()
    body = key.json()
    return {"api_key": body["key"], "public_id": str(body.get("publicId", "")), "team_uuid": team["uuid"]}
