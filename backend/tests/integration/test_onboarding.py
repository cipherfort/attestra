# SPDX-License-Identifier: Apache-2.0
"""Application registration (M2): a team registers its application from the repository contract; Tier 1/2 waits for
an AppSec decision that the requester can never make themselves; the worker turns the decision into evidence."""

from __future__ import annotations

import copy
import os

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.config import repo_root
from aap.db import transaction
from aap.services import onboarding
from aap.worker.runner import Worker

pytestmark = pytest.mark.db

TEMPLATE = yaml.safe_load((repo_root() / "templates/repo-contract/.security/application.yaml").read_text())
ASVS = (repo_root() / "templates/repo-contract/.security/asvs.yaml").read_text()


@pytest.fixture(scope="module")
def client(engine, bundle, demo):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def contract(name, unit="claims-team", **classification):
    doc = copy.deepcopy(TEMPLATE)
    doc["application"]["name"] = name
    doc["application"]["owners"]["org_unit"] = unit
    doc["application"]["classification"].update(classification)
    return yaml.safe_dump(doc)


LOW = {
    "data_classification": "internal",
    "personal_data": "none",
    "exposure": "internal",
    "user_population": "team",
    "business_criticality": "minimal",
    "privileged_integration": "none",
    "regulatory": [],
}


def register(client, login, repo, repo_id, app_yaml, asvs=ASVS):
    return client.post(
        "/api/v1/applications",
        json={"repository": repo, "repository_id": repo_id, "application_yaml": app_yaml, "asvs_yaml": asvs},
        headers=as_(login),
    )


def test_champion_registers_a_tier1_application_that_waits_for_appsec(client, engine):
    r = register(client, "ajones", "example-org/claims-portal", "910001", contract("Claims Portal"))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["tier"] == 1 and body["decision"] == "pending" and body["matched_floor_rules"]

    cls = client.get(f"/api/v1/applications/{body['id']}/classification", headers=as_("ajones")).json()
    assert cls["decision"] == "pending" and cls["requested_by"] == "Amira Jones" and cls["can_decide"] is False
    assert client.get(f"/api/v1/applications/{body['id']}/classification", headers=as_("cpatel")).json()["can_decide"]

    with transaction(engine, "aap_worker") as conn:
        repo = conn.execute(
            text("""SELECT r.provider, r.external_id, a.source_repo_id = r.id AS is_source FROM repositories r
                    JOIN application_repositories ar ON ar.repository_id = r.id
                    JOIN applications a ON a.id = ar.application_id WHERE a.id = :a"""),
            {"a": body["id"]},
        ).one()
        audited = conn.execute(
            text("SELECT count(*) FROM audit_events WHERE action = 'application.register' AND target_id = :a"),
            {"a": body["id"]},
        ).scalar_one()
    assert (repo.provider, repo.external_id, repo.is_source) == ("github", "910001", True)
    assert audited == 1

    # a champion cannot decide classifications at all; an AppSec engineer can
    deny = client.post(
        f"/api/v1/applications/{body['id']}/classification/decisions",
        json={"decision": "approved"},
        headers=as_("ajones"),
    )
    assert deny.status_code == 403
    ok = client.post(
        f"/api/v1/applications/{body['id']}/classification/decisions",
        json={"decision": "approved", "reason": "matches the service's data and exposure"},
        headers=as_("cpatel"),
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["tier"] == 1
    after = client.get(f"/api/v1/applications/{body['id']}/classification", headers=as_("ajones")).json()
    assert after["decision"] == "approved" and after["decided_by"] == "Chandra Patel" and not after["can_decide"]
    again = client.post(
        f"/api/v1/applications/{body['id']}/classification/decisions",
        json={"decision": "rejected"},
        headers=as_("hreviewer"),
    )
    assert again.status_code == 409  # nothing pending any more


def test_requester_can_never_decide_their_own_classification(client, engine):
    r = register(client, "cpatel", "example-org/benefits-gateway", "910002", contract("Benefits Gateway"))
    assert r.status_code == 201, r.text
    url = f"/api/v1/applications/{r.json()['id']}/classification/decisions"
    self_decide = client.post(url, json={"decision": "approved"}, headers=as_("cpatel"))
    assert self_decide.status_code == 403 and "segregation of duties" in self_decide.json()["detail"]
    with transaction(engine, "aap_worker") as conn:
        denied = conn.execute(
            text("""SELECT count(*) FROM audit_events WHERE action = 'classification.approved'
                    AND outcome = 'denied' AND target_id = :a"""),
            {"a": r.json()["id"]},
        ).scalar_one()
    assert denied == 1  # the refusal is audited even though the request failed
    assert client.post(url, json={"decision": "rejected", "reason": "wrong unit"}, headers=as_("hreviewer")).is_success


def test_low_tier_is_auto_approved(client):
    r = register(client, "ajones", "example-org/claims-docs", "910003", contract("Claims Docs", **LOW))
    assert r.status_code == 201, r.text
    assert r.json()["tier"] in (3, 4) and r.json()["decision"] == "auto_approved"


def test_registration_is_scoped_to_the_callers_units(client):
    r = register(client, "ajones", "example-org/hr-thing", "910004", contract("HR Thing", unit="people-systems"))
    assert r.status_code == 403  # RLS: a champion registers only into units they belong to
    engineer = register(client, "ekim", "example-org/pay-thing", "910005", contract("Pay Thing", "payments-team"))
    assert engineer.status_code == 403  # engineers have no application.register permission


def test_bad_contracts_and_duplicates_are_refused(client):
    bad = yaml.safe_load(contract("Broken"))
    del bad["application"]["owners"]
    r = register(client, "ajones", "example-org/broken", "910006", yaml.safe_dump(bad))
    assert r.status_code == 422 and "owners" in r.json()["detail"]
    unknown_unit = register(client, "cpatel", "example-org/x", "910007", contract("Unit Test App", unit="no-such-unit"))
    assert unknown_unit.status_code == 422 and "no-such-unit" in unknown_unit.json()["detail"]
    dup = register(client, "cpatel", "example-org/claims-portal-fork", "910001", contract("Claims Fork"))
    assert dup.status_code == 409 and "already registered" in dup.json()["detail"]
    no_scm = client.post("/api/v1/applications", json={"repository": "example-org/y"}, headers=as_("cpatel"))
    assert no_scm.status_code == 422 and "not configured" in no_scm.json()["detail"]


def test_worker_records_the_decision_as_evidence_and_evaluates(client, engine, bundle, blobs):
    r = register(client, "ajones", "example-org/claims-batch", "910008", contract("Claims Batch", **LOW))
    app_id = r.json()["id"]
    worker = Worker(engine, bundle, blobs=blobs)
    while worker.run_once(queues=("onboarding",)):  # earlier tests' registrations are queued too
        pass
    with transaction(engine, "aap_worker") as conn:
        ev = conn.execute(
            text("""SELECT confidence, result, summary FROM evidence
                    WHERE application_id = :a AND evidence_type = 'registry.classification'"""),
            {"a": app_id},
        ).one()
        queued = conn.execute(
            text("SELECT count(*) FROM jobs WHERE queue = 'evaluate' AND payload->>'application_id' = :a"),
            {"a": app_id},
        ).scalar_one()
    assert (ev.confidence, ev.result, ev.summary["decision"]) == ("M1", "pass", "auto_approved")
    assert queued == 1
    while worker.run_once(queues=("evaluate",)):
        pass
    controls = client.get(f"/api/v1/applications/{app_id}/controls", headers=as_("ajones")).json()["items"]
    states = {c["control_key"]: c["state"] for c in controls}
    assert states["ASC-GOV-02"] == "satisfied"  # classification_current: the auto-approved tier is the evidence


def test_human_decision_is_m2_evidence(engine, bundle, now):
    with transaction(engine, "aap_worker") as conn:
        app_id = conn.execute(text("SELECT id FROM applications WHERE name = 'Claims Portal'")).scalar_one()
        onboarding.record_classification_evidence(conn, str(app_id), now)
        ev = conn.execute(
            text("""SELECT confidence, summary FROM evidence WHERE application_id = :a
                    AND evidence_type = 'registry.classification' ORDER BY ingested_at DESC LIMIT 1"""),
            {"a": app_id},
        ).one()
    assert ev.confidence == "M2" and ev.summary == {"tier": 1, "decision": "approved"}


def test_appsec_engineer_in_the_owning_team_cannot_decide(client, engine):
    from aap.store import registry

    with transaction(engine, "aap_worker") as conn:
        unit = conn.execute(text("SELECT id FROM org_units WHERE slug = 'benefits'")).scalar_one()
        embedded = registry.upsert_user(conn, "Embedded AppSec", "iembedded")
        registry.add_member(conn, str(unit), embedded)
        registry.grant_role(conn, embedded, "appsec_engineer")
    r = register(client, "ajones", "example-org/claims-mobile", "910009", contract("Claims Mobile"))
    assert r.status_code == 201, r.text
    url = f"/api/v1/applications/{r.json()['id']}/classification/decisions"
    cls = client.get(f"/api/v1/applications/{r.json()['id']}/classification", headers=as_("iembedded")).json()
    assert cls["decision"] == "pending" and cls["can_decide"] is False
    deny = client.post(url, json={"decision": "approved"}, headers=as_("iembedded"))
    assert (
        deny.status_code == 403 and "owns this application" in deny.json()["detail"]
    )  # member of Benefits, above Claims
