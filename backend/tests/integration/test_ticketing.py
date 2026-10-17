# SPDX-License-Identifier: Apache-2.0
"""Findings → Jira (ADR-018) over the demo world: grouping, idempotency, crash recovery, closure only by evidence."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from aap.connectors.jira import MANAGED_LABEL, JiraClient, dedup_label
from aap.db import transaction
from aap.services import ticketing
from tests.jira_fake import FakeJira

pytestmark = pytest.mark.db
POLICY = {
    "ticket_priorities": ["P1", "P2", "P3"],
    "issue_type": "Task",
    "labels": ["appsec", "aap-managed"],
    "priority_map": {"P1": "Highest", "P2": "High", "P3": "Medium"},
    "default_project": "SEC",
}


@pytest.fixture
def jira():
    return FakeJira()


def run(engine, fake, policy=POLICY):
    client = JiraClient(fake.base, email="svc@example.org", api_token="t", http=fake.client())
    with transaction(engine, "aap_worker") as conn:
        return ticketing.sync(conn, client, policy, "https://aap.example.org", datetime.now(UTC))


def open_ticketable(engine):
    with transaction(engine, "aap_worker") as conn:
        return conn.execute(
            text("""SELECT id, fingerprint, status, priority FROM findings
                                    WHERE priority IN ('P1','P2','P3') AND status NOT IN ('closed','false_positive')""")
        ).all()


@pytest.fixture
def clean_tickets(engine, demo):
    from aap.db import admin_connection

    with admin_connection(engine) as conn:
        conn.execute(text("DELETE FROM aap.finding_tickets; DELETE FROM aap.tickets;"))
        conn.execute(text("UPDATE aap.findings SET status = 'new' WHERE status IN ('ticketed', 'fix_pending')"))
    yield


def test_tickets_created_once_with_minimal_content(engine, jira, clean_tickets):
    findings = open_ticketable(engine)
    assert findings, "demo world should contain P1-P3 findings"
    rep = run(engine, jira)
    assert rep.created and not rep.errors
    issue = jira.issues[rep.created[0]]
    f = issue["fields"]
    assert MANAGED_LABEL in f["labels"] and any(lbl.startswith("aap-k-") for lbl in f["labels"])
    assert f["priority"]["name"] in ("Highest", "High", "Medium") and f["summary"].startswith("[P")
    text_blob = str(f["description"])
    assert "#/findings/" in text_blob and "BEGIN" not in text_blob  # deep link, no secret material
    with transaction(engine, "aap_worker") as conn:
        statuses = {
            r.status
            for r in conn.execute(
                text("SELECT f.status FROM findings f JOIN finding_tickets ft ON ft.finding_id = f.id")
            )
        }
    assert statuses <= {"ticketed", "fix_pending", "reopened"}
    # idempotent: a second run creates nothing
    assert run(engine, jira).created == []


def test_crash_between_create_and_store_reconciles_by_label(engine, jira, clean_tickets):
    first = run(engine, jira)
    from aap.db import admin_connection

    with admin_connection(engine) as conn:  # simulate: Jira issue exists, our DB row was lost
        conn.execute(text("DELETE FROM aap.finding_tickets; DELETE FROM aap.tickets;"))
    second = run(engine, jira)
    assert second.created == [] and second.linked >= len(first.created)
    assert len(jira.issues) == len(first.created)  # no duplicates in Jira


def _fresh_ticket(engine, keys):
    """A ticket whose findings are all newly ticketed (other tests may leave reopened findings in the shared world)."""
    with transaction(engine, "aap_worker") as conn:
        for key in keys:
            statuses = set(
                conn.execute(
                    text("""SELECT f.status FROM findings f JOIN finding_tickets ft ON ft.finding_id = f.id
                        JOIN tickets t ON t.id = ft.ticket_id WHERE t.ticket_key = :k"""),
                    {"k": key},
                ).scalars()
            )
            if statuses and statuses <= {"new", "triaged", "ticketed"}:
                return key
    raise AssertionError("no freshly ticketed finding")


def test_ticket_done_does_not_close_finding_and_regression_reopens(engine, jira, clean_tickets):
    rep = run(engine, jira)
    key = _fresh_ticket(engine, rep.created)
    jira.set_status(key, "Done")
    rep2 = run(engine, jira)
    assert rep2.fix_pending >= 1
    with transaction(engine, "aap_worker") as conn:
        rows = conn.execute(
            text("""SELECT f.id, f.status FROM findings f JOIN finding_tickets ft ON ft.finding_id = f.id
                                    JOIN tickets t ON t.id = ft.ticket_id WHERE t.ticket_key = :k"""),
            {"k": key},
        ).all()
        assert {r.status for r in rows} == {"fix_pending"}  # not closed: only a re-scan closes
        # the next scan still sees it
        conn.execute(
            text("UPDATE findings SET last_seen_at = now() + interval '1 second' WHERE id = ANY(:ids)"),
            {"ids": [r.id for r in rows]},
        )
    rep3 = run(engine, jira)
    assert key in rep3.reopened_tickets and jira.issues[key]["status"] == "In Progress"
    assert "still detects" in str(jira.comments[key][-1])


def test_closure_by_evidence_closes_ticket(engine, jira, clean_tickets):
    rep = run(engine, jira)
    key = rep.created[0]
    with transaction(engine, "aap_worker") as conn:
        ids = [
            r.id
            for r in conn.execute(
                text("""SELECT ft.finding_id AS id FROM finding_tickets ft
                                                  JOIN tickets t ON t.id = ft.ticket_id WHERE t.ticket_key = :k"""),
                {"k": key},
            )
        ]
        ev = conn.execute(text("SELECT evidence_id FROM evidence LIMIT 1")).scalar_one()
        conn.execute(
            text("""UPDATE findings SET status = 'closed', closed_at = now(), closure_evidence_id = :ev
                             WHERE id = ANY(:ids)"""),
            {"ev": ev, "ids": ids},
        )
    rep2 = run(engine, jira)
    assert key in rep2.closed_tickets and jira.issues[key]["status"] == "Done"
    assert "Verified fixed" in str(jira.comments[key][-1])


def test_no_project_configured_means_no_ticket(engine, jira, clean_tickets):
    rep = run(engine, jira, {**POLICY, "default_project": None})
    assert rep.created == [] and rep.skipped_no_project > 0 and not jira.issues


def test_dedup_label_is_stable():
    assert dedup_label("dep|APP-1|acme/x|pkg:maven/org.apache.logging.log4j/log4j-core") == dedup_label(
        "dep|APP-1|acme/x|pkg:maven/org.apache.logging.log4j/log4j-core"
    )
    assert len(dedup_label("x")) == len("aap-k-") + 24


@pytest.mark.skipif(
    not os.environ.get("AAP_TEST_JIRA_URL"),
    reason="live Jira contract test: set AAP_TEST_JIRA_URL, "
    "AAP_TEST_JIRA_EMAIL, AAP_TEST_JIRA_TOKEN, AAP_TEST_JIRA_PROJECT",
)
def test_live_jira_contract():
    c = JiraClient(
        os.environ["AAP_TEST_JIRA_URL"],
        email=os.environ["AAP_TEST_JIRA_EMAIL"],
        api_token=os.environ["AAP_TEST_JIRA_TOKEN"],
    )
    key = f"fnd|contract-test-{datetime.now(UTC):%Y%m%d%H%M%S}"
    from aap.connectors.jira import adf

    issue = c.create(
        project=os.environ["AAP_TEST_JIRA_PROJECT"],
        issue_type="Task",
        summary="AAP contract test",
        description=adf("Created by the platform's live contract test; safe to delete."),
        dedup_key=key,
        labels=["aap-contract-test"],
        priority=None,
        due=None,
    )
    assert c.find_by_dedup(key).key == issue.key  # label search works (may lag a few seconds on large sites)
    assert c.transition_to(issue.key, "done")
