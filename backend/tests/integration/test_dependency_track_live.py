# SPDX-License-Identifier: Apache-2.0
"""Against a real, freshly started Dependency-Track 4.14.5: bootstrap from zero → upload the demo SBOMs → pull findings.

Opt in: AAP_TEST_SERVICES=1 (pulls the image, needs ~3 GB RAM for DT and network for the OSV Maven mirror, ~2 min).
"""

from __future__ import annotations

import os
import secrets
import subprocess
import time
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import text

from aap.connectors.dependency_track import DependencyTrackClient, DependencyTrackError, bootstrap
from aap.db import transaction
from aap.services import sbom_sync

IMAGE = "dependencytrack/apiserver:4.14.5"
pytestmark = [
    pytest.mark.db,
    pytest.mark.service,
    pytest.mark.skipif(os.environ.get("AAP_TEST_SERVICES") != "1", reason="set AAP_TEST_SERVICES=1"),
]


def _wait(predicate, timeout: float, what: str) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(2)
    raise TimeoutError(what)


def _ready(name: str) -> str:
    """Base URL once the API answers. Re-read after every restart: Docker reassigns the ephemeral host port."""
    base = ""

    def up():
        nonlocal base
        out = subprocess.run(["docker", "port", name, "8080/tcp"], capture_output=True, text=True).stdout.strip()
        if not out:
            return False
        base = f"http://127.0.0.1:{out.splitlines()[0].rsplit(':', 1)[-1]}"
        try:
            return httpx.get(f"{base}/api/version", timeout=3).status_code == 200
        except httpx.HTTPError:
            return False

    _wait(up, 240, "Dependency-Track did not start")
    return base


@pytest.fixture(scope="module")
def dt():
    name = f"aap-dt-it-{uuid.uuid4().hex[:6]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-m",
            "3g",
            "-e",
            "EXTRA_JAVA_OPTIONS=-Xmx2g",
            "-p",
            "127.0.0.1::8080",
            IMAGE,
        ],
        check=True,
        capture_output=True,
    )
    try:
        yield name, _ready(name)
    finally:
        state = subprocess.run(
            [
                "docker",
                "inspect",
                name,
                "--format",
                "{{.State.Status}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} exit={{.State.ExitCode}}",
            ],
            capture_output=True,
            text=True,
        )
        print("DT container:", state.stdout.strip())
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_bootstrap_upload_and_findings(dt, engine, demo, demo_blobs):
    name, base = dt
    password = secrets.token_urlsafe(24)
    creds = bootstrap(base, password, osv_ecosystems="Maven")
    assert creds["api_key"].startswith("odt_")
    # idempotent second run (already-changed password, existing team) mints a fresh key and grants nothing new
    assert bootstrap(base, password, osv_ecosystems="Maven")["team_uuid"] == creds["team_uuid"]
    with pytest.raises(DependencyTrackError):
        bootstrap(base, "wrong-password")

    # the OSV mirror runs at startup: restart so the Maven advisories are mirrored now (prod: daily schedule)
    subprocess.run(["docker", "restart", name], check=True, capture_output=True)
    _wait(
        lambda: (
            "Google OSV mirroring complete"
            in subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
        ),
        300,
        "OSV mirror",
    )
    base = _ready(name)

    client = DependencyTrackClient(base, creds["api_key"])
    report = sbom_sync.DtReport()
    with transaction(engine, "aap_worker") as conn:
        conn.execute(text("UPDATE sboms SET dtrack_project_uuid = NULL"))
        sbom_sync.upload_current(conn, client, demo_blobs, report)
    assert report.uploaded >= 1 and not report.errors

    def has_findings():
        with transaction(engine, "aap_worker") as conn:
            r = sbom_sync.DtReport()
            sbom_sync.pull_findings(conn, client, datetime.now(UTC), r)
            return r.findings > 0

    _wait(has_findings, 120, "DT analysis produced no findings")
    with transaction(engine, "aap_worker") as conn:
        v = conn.execute(
            text("SELECT vuln_key, aliases, in_kev FROM vulnerabilities WHERE vuln_key = 'CVE-2021-44228'")
        ).one()
        n = conn.execute(text("SELECT count(*) FROM findings WHERE source_system = 'dependency_track'")).scalar_one()
    assert v.in_kev, "a DT sync must never clear the CISA KEV flag set by the KEV feed"
    assert "GHSA-jfh8-c2jp-5v3q" in v.aliases and n >= 1
    # the team key cannot administer DT
    r = httpx.get(f"{base}/api/v1/team", headers={"X-Api-Key": creds["api_key"]})
    assert r.status_code == 403
