# SPDX-License-Identifier: Apache-2.0
"""Notifications: things a person must act on, sent to a chat channel through an incoming webhook (Slack, Microsoft
Teams Workflows, Mattermost, or anything that accepts `{"text": ...}`).

collect()   scheduler: derive events from current state, each with a stable key, into the outbox (topic `notify`)
            once only (the key is the deduplication):
              * a Tier 1/2 classification is waiting for AppSec          classification.pending:<app>
              * an exception is waiting for a decision                   exception.pending:<key>
              * an approved exception expires in 30/14/3 days            exception.expiring:<key>:<days>
              * a P1 finding is open                                     finding.p1:<id>
dispatch()  the `webhook` plugin: POST each pending event; mark it dispatched only when the endpoint accepted it.

Messages carry identifiers and links, never finding details or evidence content (a chat channel is not a
security boundary).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

TOPIC = "notify"


def _queue(conn: Connection, key: str, text_: str, link: str) -> bool:
    row = conn.execute(
        text("""INSERT INTO outbox (topic, payload)
                SELECT :t, CAST(:p AS jsonb)
                WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE topic = :t AND payload->>'key' = :k)
                RETURNING id"""),
        {"t": TOPIC, "k": key, "p": json.dumps({"key": key, "text": text_, "link": link})},
    ).first()
    return row is not None


def collect(conn: Connection, bundle: Any, now: datetime, public_url: str = "") -> int:
    base = public_url.rstrip("/")
    queued = 0
    for r in conn.execute(
        text("""SELECT a.app_key, a.name, c.computed_tier FROM application_classifications c
                JOIN applications a ON a.id = c.application_id
                WHERE c.decision = 'pending'
                  AND NOT EXISTS (SELECT 1 FROM application_classifications s WHERE s.supersedes_id = c.id)""")
    ):
        queued += _queue(
            conn,
            f"classification.pending:{r.app_key}",
            f"Classification waiting for AppSec: {r.app_key} {r.name} (computed Tier {r.computed_tier})",
            f"{base}/#/apps/{r.app_key}",
        )
    for r in conn.execute(
        text("""SELECT x.exception_key, x.residual_priority, a.app_key FROM exceptions x
                JOIN applications a ON a.id = x.application_id WHERE x.status = 'pending_approval'""")
    ):
        queued += _queue(
            conn,
            f"exception.pending:{r.exception_key}",
            f"Exception {r.exception_key} ({r.residual_priority}, {r.app_key}) is waiting for a decision",
            f"{base}/#/exceptions/{r.exception_key}",
        )
    days_list = sorted((bundle.doc("exception_policy").get("review_reminders_days_before_expiry") or []), reverse=True)
    for r in conn.execute(
        text("""SELECT x.exception_key, x.expires_at, a.app_key FROM exceptions x
                JOIN applications a ON a.id = x.application_id WHERE x.status = 'approved' AND x.expires_at > :now"""),
        {"now": now},
    ):
        left = (r.expires_at - now).days
        due = [d for d in days_list if left <= int(d)]
        if due:
            d = min(due)
            queued += _queue(
                conn,
                f"exception.expiring:{r.exception_key}:{d}",
                f"Exception {r.exception_key} ({r.app_key}) expires in {left} day(s): renew or remediate",
                f"{base}/#/exceptions/{r.exception_key}",
            )
    for r in conn.execute(
        text("""SELECT f.id, a.app_key FROM findings f JOIN applications a ON a.id = f.application_id
                WHERE f.priority = 'P1' AND f.status NOT IN ('closed', 'false_positive', 'excepted')
                  AND f.first_seen_at > :since"""),
        {"since": now - timedelta(days=30)},
    ):
        queued += _queue(
            conn, f"finding.p1:{r.id}", f"New P1 finding in {r.app_key}: fix within 7 days", f"{base}/#/findings/{r.id}"
        )
    return queued


def pending(conn: Connection, limit: int = 100) -> list[Mapping[str, Any]]:
    return [
        {"id": r.id, **r.payload}
        for r in conn.execute(
            text("""SELECT id, payload FROM outbox WHERE topic = :t AND dispatched_at IS NULL ORDER BY id LIMIT :n
                    FOR UPDATE SKIP LOCKED"""),
            {"t": TOPIC, "n": limit},
        )
    ]


def mark_sent(conn: Connection, outbox_id: int) -> None:
    conn.execute(text("UPDATE outbox SET dispatched_at = now() WHERE id = :i"), {"i": outbox_id})


def message(event: Mapping[str, Any]) -> dict[str, Any]:
    """Slack/Mattermost `text`; Teams Workflows ("post to a channel when a webhook request is received") read it too."""
    link = event.get("link") or ""
    return {"text": f"{event['text']}" + (f"\n{link}" if link else ""), "key": event["key"]}
