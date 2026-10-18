# SPDX-License-Identifier: Apache-2.0
"""Finding → Jira ticket sync (ADR-018). The platform is the only ticket writer.

create:     open P1–P3 findings grouped by deterministic dedup key (one upgrade fixing five CVEs is one ticket);
            lookup (DB, then Jira label) before create, so a crash between create and store reconciles itself.
reconcile:  Jira "done"            + finding still open   → finding fix_pending (awaiting a re-scan; ticket ≠ fix)
            all findings closed by evidence + ticket open → ticket → done, comment with the closing evidence
            finding seen again after fix_pending          → finding reopened, ticket reopened with a comment
Ticket state never closes a finding: only a re-scan does (schema test T4).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.connectors.jira import adf
from aap.ids import uuid7
from aap.plugins.interfaces import TicketError, TicketSystem
from aap.store.findings_store import OPEN_STATUSES

PURL_VERSION_SEP = "@"


def dedup_key(f: Any) -> str:
    if f.finding_type == "dependency" and f.purl:
        return f"dep|{f.app_key}|{f.scope_ref}|{f.purl.split(PURL_VERSION_SEP, 1)[0]}"
    if f.finding_type == "container" and f.purl:
        return f"ctr|{f.app_key}|{f.scope_ref}|{f.purl.split(PURL_VERSION_SEP, 1)[0]}"
    if f.finding_type == "control_gap" and f.control_key:
        return f"gap|{f.app_key}|{f.control_key}"
    return f"fnd|{f.fingerprint}"


@dataclass
class SyncReport:
    created: list[str] = field(default_factory=list)
    linked: int = 0
    fix_pending: int = 0
    closed_tickets: list[str] = field(default_factory=list)
    reopened_tickets: list[str] = field(default_factory=list)
    skipped_no_project: int = 0
    errors: list[str] = field(default_factory=list)


def _event(
    conn: Connection, finding_id: str, kind: str, frm: str | None, to: str | None, details: dict[str, Any]
) -> None:
    conn.execute(
        text("""INSERT INTO finding_events (id, finding_id, event_type, from_status, to_status, actor_type, actor_id, details)
                VALUES (:id, :f, :t, CAST(:fs AS finding_status), CAST(:ts AS finding_status), 'system', 'jira-sync',
                        CAST(:d AS jsonb))"""),
        {"id": uuid7(), "f": finding_id, "t": kind, "fs": frm, "ts": to, "d": json.dumps(details, default=str)},
    )


def _set_status(conn: Connection, finding_id: str, frm: str, to: str, kind: str, details: dict[str, Any]) -> None:
    conn.execute(
        text("UPDATE findings SET status = CAST(:s AS finding_status) WHERE id = :id"), {"s": to, "id": finding_id}
    )
    _event(conn, finding_id, kind, frm, to, details)


def _project_for(policy: dict[str, Any], org_slugs: list[str]) -> str | None:
    by_unit = policy.get("default_project_by_org_unit") or {}
    for slug in org_slugs:  # nearest unit first
        if slug in by_unit:
            return str(by_unit[slug])
    return policy.get("default_project")


def sync(conn: Connection, jira: TicketSystem, policy: dict[str, Any], platform_url: str, now: datetime) -> SyncReport:
    rep = SyncReport()
    rows = conn.execute(
        text("""SELECT f.id, f.fingerprint, f.finding_type, f.scope_ref, f.control_key, f.status, f.priority, f.title,
                       f.sla_due_at, f.cwe_id, f.application_id, a.app_key, a.name AS app_name, c.purl,
                       (SELECT array_agg(o.slug ORDER BY o.depth DESC) FROM (
                          WITH RECURSIVE up AS (SELECT id, parent_id, slug, 0 AS depth FROM org_units WHERE id = a.org_unit_id
                            UNION ALL SELECT p.id, p.parent_id, p.slug, up.depth + 1 FROM org_units p JOIN up ON p.id = up.parent_id)
                          SELECT slug, depth FROM up) o) AS org_slugs
                FROM findings f JOIN applications a ON a.id = f.application_id
                LEFT JOIN components c ON c.id = f.component_id
                WHERE f.status = ANY(:open) AND f.priority = ANY(CAST(:pri AS priority_level[]))
                  AND NOT EXISTS (SELECT 1 FROM finding_tickets ft WHERE ft.finding_id = f.id)"""),
        {"open": list(OPEN_STATUSES), "pri": list(policy.get("ticket_priorities") or ["P1", "P2", "P3"])},
    ).all()

    groups: dict[str, list[Any]] = defaultdict(list)
    for f in rows:
        groups[dedup_key(f)].append(f)

    for key, members in groups.items():
        head = min(members, key=lambda f: (f.priority, f.sla_due_at or now))
        ticket = conn.execute(text("SELECT id, ticket_key, url FROM tickets WHERE dedup_key = :k"), {"k": key}).first()
        try:
            if ticket is None:
                project = _project_for(policy, list(head.org_slugs or []))
                issue = jira.find_by_dedup(key, project)
                if issue is None:
                    if not project:
                        rep.skipped_no_project += len(members)
                        continue
                    n = len(members)
                    summary = f"[{head.priority}] {head.app_name}: {head.title}" + (
                        f" (+{n - 1} related)" if n > 1 else ""
                    )
                    issue = jira.create(
                        project=project,
                        issue_type=str(policy.get("issue_type") or "Task"),
                        summary=summary,
                        description=adf(
                            f"Application: {head.app_name} ({head.app_key}). Priority {head.priority} from the platform "
                            f"risk model; due {head.sla_due_at:%Y-%m-%d} (SLA)."
                            if head.sla_due_at
                            else f"Application: {head.app_name} ({head.app_key}). Priority {head.priority}.",
                            f"{n} finding(s) in {head.scope_ref}. Closing this ticket does not close the findings: "
                            "the next scan verifies the fix.",
                            link=("Open in FortProof", f"{platform_url}/#/findings/{head.id}"),
                        ),
                        dedup_key=key,
                        labels=[
                            *(policy.get("labels") or []),
                            f"aap-{head.priority}",
                            *([f"CWE-{head.cwe_id}"] if head.cwe_id else []),
                            *([head.control_key] if head.control_key else []),
                        ],
                        priority=(policy.get("priority_map") or {}).get(head.priority),
                        due=head.sla_due_at.date() if head.sla_due_at else None,
                    )
                    rep.created.append(issue.key)
                tid = uuid7()
                conn.execute(
                    text("""INSERT INTO tickets (id, system, ticket_key, dedup_key, application_id, external_status, url, last_synced_at)
                            VALUES (:id, :sys, :k, :d, :a, :s, :u, now())
                            ON CONFLICT (dedup_key) DO UPDATE SET last_synced_at = now() RETURNING id, ticket_key, url"""),
                    {
                        "id": tid,
                        "sys": getattr(jira, "system", "jira"),
                        "k": issue.key,
                        "d": key,
                        "a": head.application_id,
                        "s": issue.status,
                        "u": issue.url,
                    },
                )
                ticket = conn.execute(
                    text("SELECT id, ticket_key, url FROM tickets WHERE dedup_key = :k"), {"k": key}
                ).first()
        except TicketError as e:
            rep.errors.append(f"{key}: {e}")
            continue
        assert ticket is not None
        for f in members:
            conn.execute(
                text("INSERT INTO finding_tickets (finding_id, ticket_id) VALUES (:f, :t) ON CONFLICT DO NOTHING"),
                {"f": f.id, "t": ticket.id},
            )
            rep.linked += 1
            if f.status in ("new", "triaged"):
                _set_status(conn, str(f.id), f.status, "ticketed", "ticketed", {"ticket": ticket.ticket_key})
            else:
                _event(conn, str(f.id), "ticketed", None, None, {"ticket": ticket.ticket_key})

    reconcile(conn, jira, rep)
    return rep


def reconcile(conn: Connection, jira: TicketSystem, rep: SyncReport) -> None:
    tickets = conn.execute(
        text("""SELECT t.id, t.ticket_key,
                       array_agg(json_build_object(
                         'id', f.id, 'status', f.status, 'closure', f.closure_evidence_id, 'last_seen', f.last_seen_at,
                         'fix_pending_at', (SELECT max(e.at) FROM finding_events e
                                            WHERE e.finding_id = f.id AND e.to_status = 'fix_pending'))) AS findings
                FROM tickets t JOIN finding_tickets ft ON ft.ticket_id = t.id JOIN findings f ON f.id = ft.finding_id
                WHERE t.system = :sys GROUP BY t.id"""),
        {"sys": getattr(jira, "system", "jira")},
    ).all()
    for t in tickets:
        try:
            issue = jira.get(t.ticket_key)
            _reconcile_one(conn, jira, rep, t.ticket_key, issue.status_category, t.findings)
        except TicketError as e:
            rep.errors.append(f"{t.ticket_key}: {e}")
            continue
        conn.execute(
            text("UPDATE tickets SET external_status = :s, last_synced_at = now() WHERE id = :id"),
            {"s": issue.status, "id": t.id},
        )


def _reconcile_one(
    conn: Connection, jira: TicketSystem, rep: SyncReport, key: str, category: str, fs: list[dict[str, Any]]
) -> None:
    open_fs = [f for f in fs if f["status"] in OPEN_STATUSES]
    if category == "done":
        regressed = False
        for f in open_fs:
            if f["status"] in ("new", "triaged", "ticketed"):
                _set_status(
                    conn,
                    f["id"],
                    f["status"],
                    "fix_pending",
                    "status_changed",
                    {"ticket": key, "reason": "ticket done; awaiting verification by re-scan"},
                )
                rep.fix_pending += 1
            elif f["status"] == "fix_pending" and f["fix_pending_at"] and f["last_seen"] > f["fix_pending_at"]:
                _set_status(
                    conn,
                    f["id"],
                    "fix_pending",
                    "reopened",
                    "verification_failed",
                    {"ticket": key, "reason": "still detected by a scan after the ticket was done"},
                )
                regressed = True
            elif f["status"] == "reopened":
                regressed = True
        if regressed and jira.transition_to(key, "indeterminate", prefer=("In Progress", "Reopened")):
            jira.comment(key, adf("The platform still detects this issue in a newer scan. Reopened automatically."))
            rep.reopened_tickets.append(key)
    elif not open_fs and any(f["closure"] for f in fs):
        if jira.transition_to(key, "done", prefer=("Done", "Closed")):
            jira.comment(
                key,
                adf("Verified fixed: the latest scan no longer reports this issue. Closed automatically by FortProof."),
            )
            rep.closed_tickets.append(key)
