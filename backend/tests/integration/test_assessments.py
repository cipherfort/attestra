# SPDX-License-Identifier: Apache-2.0
"""Manual assessments: who may record and decide, M1 vs M2 from the approver's independence, evidence written by
the worker only, attestations scoped to their control, and SAMM interview answers feeding maturity."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aap.api.app import create_app
from aap.db import transaction
from aap.store import registry
from aap.worker.runner import Worker

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def app_id(fresh_app):
    return fresh_app("Assessments Test App", "990101")


@pytest.fixture(scope="module")
def client(engine, bundle, demo, app_id):
    os.environ["AAP_AUTH_MODE"] = "dev"
    os.environ["AAP_ENV"] = "development"
    with transaction(engine, "aap_worker") as conn:  # an AppSec engineer embedded in the owning business unit
        unit = conn.execute(text("SELECT id FROM org_units WHERE slug = 'benefits'")).scalar_one()
        inside = registry.upsert_user(conn, "Embedded Reviewer", "ireviewer")
        registry.add_member(conn, str(unit), inside)
        registry.grant_role(conn, inside, "appsec_engineer")
    return TestClient(create_app(engine, bundle))


def as_(login):
    return {"X-AAP-Dev-User": login}


def drain(engine, bundle, queue):
    w = Worker(engine, bundle)
    while w.run_once(queues=(queue,)):
        pass


def evidence(engine, assessment_id):
    with transaction(engine, "aap_worker") as conn:
        return conn.execute(
            text("""SELECT e.evidence_type, e.confidence, e.result, e.summary, e.producer_type FROM assessments s
                    JOIN evidence e ON e.evidence_id = s.evidence_id WHERE s.id = :s"""),
            {"s": assessment_id},
        ).first()


def test_manual_control_attestation_independent_approval_is_m2(client, engine, bundle, app_id):
    r = client.post(
        "/api/v1/assessments",
        headers=as_("ajones"),
        json={"type": "manual_control", "application": app_id, "scope": {"control_key": "ASC-REQ-03"}},
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert r.json()["can_record"] and not r.json()["can_decide"]
    bad = client.put(f"/api/v1/assessments/{sid}/answers", json={"control_key": "ASC-SRC-01"}, headers=as_("ajones"))
    assert bad.status_code == 422 and "not assessed manually" in bad.json()["detail"]
    early = client.post(f"/api/v1/assessments/{sid}/submit", headers=as_("ajones"))
    assert early.status_code == 422 and "outcome" in early.json()["detail"]  # nothing recorded yet
    assert (
        client.put(f"/api/v1/assessments/{sid}/answers", headers=as_("cpatel"), json={"outcome": "pass"}).status_code
        == 403
    )
    rec = client.put(
        f"/api/v1/assessments/{sid}/answers",
        headers=as_("ajones"),
        json={"outcome": "pass", "method": "Supplier contracts and DPAs reviewed for all three services"},
    )
    assert rec.status_code == 200 and rec.json()["status"] == "in_progress"
    assert client.post(f"/api/v1/assessments/{sid}/submit", headers=as_("ajones")).json()["status"] == "submitted"
    assert (
        client.post(
            f"/api/v1/assessments/{sid}/decision", headers=as_("ajones"), json={"outcome": "approve", "comment": "self"}
        ).status_code
        == 403
    )  # no approve permission
    ok = client.post(
        f"/api/v1/assessments/{sid}/decision",
        headers=as_("cpatel"),
        json={"outcome": "approve", "comment": "contracts checked"},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert evidence(engine, sid) is None  # the API never writes evidence
    drain(engine, bundle, "assessment")
    ev = evidence(engine, sid)
    assert (ev.evidence_type, ev.confidence, ev.result, ev.producer_type) == (
        "assessment.manual_control",
        "M2",
        "pass",
        "manual",
    )
    assert ev.summary["control_key"] == "ASC-REQ-03" and ev.summary["approved_by"] == "Chandra Patel"


def test_approver_inside_the_owning_unit_gives_m1(client, engine, bundle, app_id):
    sid = client.post(
        "/api/v1/assessments",
        headers=as_("ajones"),
        json={
            "type": "threat_model_review",
            "application": app_id,
            "scope": {"outcome": "approved", "model_commit": "a" * 40},
        },
    ).json()["id"]
    client.post(f"/api/v1/assessments/{sid}/submit", headers=as_("ajones"))
    assert (
        client.post(
            f"/api/v1/assessments/{sid}/decision",
            headers=as_("ireviewer"),
            json={"outcome": "approve", "comment": "team review"},
        ).status_code
        == 200
    )
    drain(engine, bundle, "assessment")
    ev = evidence(engine, sid)
    assert ev.evidence_type == "assessment.threat_model" and ev.confidence == "M1"


def test_attestation_for_one_control_never_satisfies_another():
    from datetime import UTC, datetime

    from aap.domain.controls import AppFacts, EvidenceView
    from aap.evaluators.base import EvaluationInput
    from aap.evaluators.base import registry as evaluators

    now = datetime.now(UTC)
    other = EvidenceView("e1", "assessment.manual_control", "M2", "pass", "active", now, {"control_key": "ASC-REQ-03"})
    i = EvaluationInput({"id": "ASC-OPS-02"}, AppFacts("a", 1, {}), [other], [], now, {}, "M2")
    assert evaluators["manual_attestation@1"](i).state.value == "no_evidence"
    mine = EvidenceView("e2", "assessment.manual_control", "M2", "pass", "active", now, {"control_key": "ASC-OPS-02"})
    i = EvaluationInput({"id": "ASC-OPS-02"}, AppFacts("a", 1, {}), [other, mine], [], now, {}, "M2")
    assert evaluators["manual_attestation@1"](i).state.value == "satisfied"


def test_samm_interview_answers_feed_maturity(client, engine, bundle, app_id):
    r = client.post(
        "/api/v1/assessments",
        headers=as_("ajones"),
        json={"type": "samm_application", "application": app_id, "scope": {"answers": {"D-TA-A:9": 1}}},
    )
    assert r.status_code == 422 and "STREAM:LEVEL" in r.json()["detail"]
    sid = client.post(
        "/api/v1/assessments",
        headers=as_("ajones"),
        json={
            "type": "samm_application",
            "application": app_id,
            "scope": {"answers": {"G-EG-A:1": 1, "G-EG-A:2": 0.5}},
        },
    ).json()["id"]
    assert (
        client.put(
            f"/api/v1/assessments/{sid}/answers", headers=as_("ajones"), json={"answers": {"G-EG-A:1": 0.3}}
        ).status_code
        == 422
    )  # not a SAMM answer option
    assert client.post(f"/api/v1/assessments/{sid}/submit", headers=as_("ajones")).status_code == 200
    dec = client.post(
        f"/api/v1/assessments/{sid}/decision",
        headers=as_("cpatel"),
        json={"outcome": "approve", "comment": "interview notes reviewed"},
    )
    assert dec.status_code == 200, dec.text
    drain(engine, bundle, "assessment")
    assert evidence(engine, sid).summary["answers"] == {"G-EG-A:1": "1.0", "G-EG-A:2": "0.5"}
    from aap.services.assessments import manual_samm_answers

    with transaction(engine, "aap_worker") as conn:
        assert manual_samm_answers(conn, app_id)[("G-EG-A", 1)] == (1.0, "M2")
    listing = client.get(f"/api/v1/assessments?application={app_id}", headers=as_("ajones")).json()["items"]
    assert {i["type"] for i in listing} >= {"manual_control", "samm_application"}
    assert client.get(f"/api/v1/assessments/{sid}", headers=as_("ekim")).status_code == 404  # out of scope
