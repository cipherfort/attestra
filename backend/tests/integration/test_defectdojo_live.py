# SPDX-License-Identifier: Apache-2.0
"""Against a real DefectDojo 3.4.0 started from deploy/local/compose.yaml: bootstrap → forward SARIF → dedup → scope.

Opt in: AAP_TEST_SERVICES=1 and AAP_TEST_DD_URL + AAP_TEST_DD_ADMIN_PASSWORD (the stack takes ~3 min to initialise,
so the test uses a running one: `docker compose -f deploy/local/compose.yaml --profile scanners up -d`).
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from aap.connectors.defectdojo import ORGANIZATION, DefectDojoClient, DefectDojoError, bootstrap

pytestmark = [
    pytest.mark.service,
    pytest.mark.skipif(
        not (os.environ.get("AAP_TEST_SERVICES") == "1" and os.environ.get("AAP_TEST_DD_URL")),
        reason="set AAP_TEST_SERVICES=1, AAP_TEST_DD_URL, AAP_TEST_DD_ADMIN_PASSWORD",
    ),
]

SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/sql-injection",
                                "shortDescription": {"text": "SQL injection"},
                                "properties": {
                                    "security-severity": "8.8",
                                    "tags": ["security", "external/cwe/cwe-089"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "js/sql-injection",
                        "level": "error",
                        "message": {"text": "Query built from user input"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.js"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
).encode()


def test_bootstrap_forward_and_scope():
    base, pw = os.environ["AAP_TEST_DD_URL"], os.environ["AAP_TEST_DD_ADMIN_PASSWORD"]
    stored = os.environ.get("AAP_TEST_DD_SERVICE_PASSWORD")  # set when the stack was bootstrapped before
    creds = bootstrap(base, "admin", pw, stored)
    with pytest.raises(DefectDojoError, match="already exists"):
        bootstrap(base, "admin", pw)  # re-run without the stored password: refused, explained
    again = bootstrap(base, "admin", pw, creds["service_password"])  # idempotent
    assert again["user_id"] == creds["user_id"]
    with pytest.raises(DefectDojoError):
        bootstrap(base, "admin", "wrong")

    dd = DefectDojoClient(base, again["api_token"])
    first = dd.reimport(
        scan_type="SARIF",
        data=SARIF,
        filename="sast.sarif",
        product="APP-IT-1",
        engagement="CI/CD acme/claims-api",
        test_title="scan.sast acme/claims-api",
    )
    second = dd.reimport(
        scan_type="SARIF",
        data=SARIF,
        filename="sast.sarif",
        product="APP-IT-1",
        engagement="CI/CD acme/claims-api",
        test_title="scan.sast acme/claims-api",
    )
    assert first["test"] == second["test"]
    findings = dd.findings(first["test"])
    assert len(findings) == 1 and findings[0]["cwe"] == 89 and findings[0]["file_path"] == "src/db.js"

    h = {"Authorization": f"Token {again['api_token']}"}
    api = base.rstrip("/") + "/api/v2"
    orgs = httpx.get(f"{api}/organizations/", headers=h).json()["results"]
    assert [o["name"] for o in orgs] == [ORGANIZATION]  # sees only its own organization
    assert httpx.get(f"{api}/users/", headers=h).status_code == 403  # cannot administer
    assert httpx.post(f"{api}/organizations/", headers=h, json={"name": "escape"}).status_code == 403
