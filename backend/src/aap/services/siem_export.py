# SPDX-License-Identifier: Apache-2.0
"""Curated security events → SIEM (ADR-020, config/siem-events.yaml). Only listed event types ever leave the platform.

derive():   computes events from ledger state on each sweep, deduplicated per `dedup_window` (outbox history),
            and writes them to the transactional outbox (topic `siem`).
dispatch(): sends undispatched outbox rows to the one configured sink (Sentinel, HTTPS/Splunk HEC or syslog,
            connectors/siem_sinks.py) and marks them dispatched; on failure they stay queued.

Derived here: secret.exposed_active, package.malicious_detected, vuln.kev_internet_exposed, finding.p1_sla_breached,
evidence.untrusted_producer, authz.sod_violation_attempt, finding.mass_closure_anomaly, checkpoint.daily.
Emitted at source: evidence.integrity_failure (scheduler). Not emitted by the platform: data.bulk_export (export
endpoints not built yet), platform.privileged_activation (Entra PIM logs reach Sentinel through Entra's own connector).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aap.connectors.sentinel import SentinelError
from aap.ids import uuid7

WINDOW = re.compile(r"^(\d+)([hd])$")


def _window(spec: str | None) -> timedelta | None:
    m = WINDOW.match(str(spec or ""))
    if not m:
        return None
    return timedelta(hours=int(m[1])) if m[2] == "h" else timedelta(days=int(m[1]))


@dataclass
class Candidate:
    event_type: str
    dedup: str
    app_key: str | None = None
    app_tier: int | None = None
    repo: str | None = None
    resource_ids: tuple[str, ...] = ()
    vuln_ids: tuple[str, ...] = ()
    actor: str | None = None
    details: dict[str, Any] | None = None


QUERIES: dict[str, str] = {
    "secret.exposed_active": """
        SELECT 'secret.exposed_active' AS t, f.id::text AS dedup, a.app_key, a.tier_rank, f.scope_ref AS repo,
               ARRAY[f.id::text] AS res, ARRAY[]::text[] AS vulns, NULL AS actor
        FROM findings f JOIN applications a ON a.id = f.application_id
        WHERE f.finding_type = 'secret' AND f.status IN ('new','triaged','ticketed','fix_pending','reopened')
          AND coalesce(f.location->>'validity', 'unknown') IN ('active', 'unknown')""",
    "package.malicious_detected": """
        SELECT 'package.malicious_detected', f.id::text, a.app_key, a.tier_rank, f.scope_ref, ARRAY[f.id::text],
               ARRAY[coalesce(v.vuln_key, '')], NULL
        FROM findings f JOIN applications a ON a.id = f.application_id LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
        WHERE (f.finding_type = 'malicious_package' OR v.is_malicious)
          AND f.status IN ('new','triaged','ticketed','fix_pending','reopened')""",
    "vuln.kev_internet_exposed": """
        SELECT 'vuln.kev_internet_exposed', a.id::text || ':' || v.vuln_key, a.app_key, a.tier_rank, min(f.scope_ref),
               array_agg(f.id::text), ARRAY[v.vuln_key] || v.aliases, NULL
        FROM findings f JOIN applications a ON a.id = f.application_id JOIN vulnerabilities v ON v.id = f.vulnerability_id
        WHERE v.in_kev AND a.exposure IN ('internet_public', 'internet_authenticated')
          AND f.status IN ('new','triaged','ticketed','fix_pending','reopened')
        GROUP BY a.id, a.app_key, a.tier_rank, v.vuln_key, v.aliases""",
    "finding.p1_sla_breached": """
        SELECT 'finding.p1_sla_breached', f.id::text, a.app_key, a.tier_rank, f.scope_ref, ARRAY[f.id::text],
               ARRAY[]::text[], NULL
        FROM findings f JOIN applications a ON a.id = f.application_id
        WHERE f.priority = 'P1' AND f.sla_breached AND f.status IN ('new','triaged','ticketed','fix_pending','reopened')""",
    "evidence.untrusted_producer": """
        SELECT 'evidence.untrusted_producer', r.repository_provider || ':' || r.repository_external_id, NULL, NULL, max(rep.full_name),
               array_agg(r.id::text), ARRAY[]::text[], NULL
        FROM evidence_rejections r LEFT JOIN repositories rep
          ON rep.provider = r.repository_provider AND rep.external_id = r.repository_external_id
        WHERE r.received_at > now() - interval '24 hours'
          AND r.reason_code IN ('UNTRUSTED_PRODUCER', 'UNAPPROVED_WORKFLOW_REF', 'DIGEST_MISMATCH', 'ATTESTATION_INVALID')
        GROUP BY r.repository_provider, r.repository_external_id HAVING count(*) >= 3""",
    "authz.sod_violation_attempt": """
        SELECT 'authz.sod_violation_attempt', e.actor_id || ':' || e.action, a.app_key, a.tier_rank, NULL,
               array_agg(e.target_id), ARRAY[]::text[], e.actor_id
        FROM audit_events e LEFT JOIN applications a ON a.id = e.application_id
        WHERE e.outcome = 'denied' AND e.details->>'reason' = 'SOD_VIOLATION' AND e.at > now() - interval '1 hour'
        GROUP BY e.actor_id, e.action, a.app_key, a.tier_rank""",
    "finding.mass_closure_anomaly": """
        SELECT 'finding.mass_closure_anomaly', f.source_system::text, NULL, NULL, NULL, ARRAY[]::text[],
               ARRAY[]::text[], NULL
        FROM findings f WHERE f.closed_at > now() - interval '1 hour'
        GROUP BY f.source_system HAVING count(*) > 100""",
}


def derive(conn: Connection, policy: dict[str, Any], now: datetime, platform_url: str) -> int:
    """Write new events to the outbox. Returns the number written."""
    types = {e["type"]: e for e in policy["events"]}
    written = 0
    for etype, sql in QUERIES.items():
        if etype not in types:
            continue
        for row in conn.execute(text(sql)).all():
            c = Candidate(
                row[0], row[1], row[2], row[3], row[4], tuple(row[5] or ()), tuple(x for x in row[6] or () if x), row[7]
            )
            written += _enqueue(conn, types[etype], c, now, platform_url)
    if "checkpoint.daily" in types:
        written += _checkpoint(conn, types["checkpoint.daily"], now, platform_url)
    return written


def _recent(conn: Connection, etype: str, dedup: str, window: timedelta | None, now: datetime) -> bool:
    if window is None:
        return False
    return (
        conn.execute(
            text("""SELECT 1 FROM outbox WHERE topic = 'siem' AND payload->>'EventType' = :t
                AND payload->'Details'->>'dedup' = :d AND created_at > :since LIMIT 1"""),
            {"t": etype, "d": dedup, "since": now - window},
        ).first()
        is not None
    )


def _enqueue(conn: Connection, spec: dict[str, Any], c: Candidate, now: datetime, platform_url: str) -> int:
    window = _window(spec.get("dedup_window"))
    if spec.get("dedup_window") not in (None, "none") and _recent(conn, c.event_type, c.dedup, window, now):
        return 0
    row = {
        "TimeGenerated": now.isoformat(),
        "EventId": str(uuid7()),
        "EventType": c.event_type,
        "Severity": spec["severity"],
        "AppKey": c.app_key,
        "AppTier": c.app_tier,
        "Repo": c.repo,
        "ResourceIds": list(c.resource_ids)[:50],
        "VulnIds": list(c.vuln_ids)[:20],
        "Actor": c.actor,
        "PlatformUrl": platform_url,
        "CorrelationId": c.dedup,
        "Details": {"dedup": c.dedup, **(c.details or {})},
    }
    conn.execute(text("INSERT INTO outbox (topic, payload) VALUES ('siem', CAST(:p AS jsonb))"), {"p": json.dumps(row)})
    return 1


def _checkpoint(conn: Connection, spec: dict[str, Any], now: datetime, platform_url: str) -> int:
    """Once a day: the current head hash of each hash-chained ledger, as an external tamper-evidence anchor."""
    day = now.strftime("%Y-%m-%d")
    if conn.execute(
        text("""SELECT 1 FROM outbox WHERE topic = 'siem' AND payload->>'EventType' = 'checkpoint.daily'
                            AND payload->>'CorrelationId' = :d"""),
        {"d": day},
    ).first():
        return 0
    evidence_head = conn.execute(
        text("SELECT encode(record_hash, 'hex') FROM evidence ORDER BY ingested_at DESC, evidence_id DESC LIMIT 1")
    ).scalar()
    audit_head = conn.execute(
        text("SELECT encode(record_hash, 'hex') FROM audit_events ORDER BY at DESC, id DESC LIMIT 1")
    ).scalar()
    details = {"evidence_chain": f"evidence_{now:%Y_%m}", "evidence_head": evidence_head, "audit_head": audit_head}
    return _enqueue(
        conn, {**spec, "dedup_window": "none"}, Candidate("checkpoint.daily", day, details=details), now, platform_url
    )


def integrity_failure(conn: Connection, policy: dict[str, Any], now: datetime, broken_index: int, checked: int) -> None:
    """Emitted at source by the scheduler's chain verification (never deduplicated away within its 1 h window
    for a different break)."""
    spec = next(e for e in policy["events"] if e["type"] == "evidence.integrity_failure")
    _enqueue(
        conn,
        spec,
        Candidate(
            "evidence.integrity_failure",
            f"{now:%Y_%m}:{broken_index}",
            details={"broken_index": broken_index, "records_checked": checked},
        ),
        now,
        "",
    )


def dispatch(conn: Connection, client: Any, limit: int = 500) -> tuple[int, str | None]:
    """Send pending SIEM rows. Returns (sent, error). Rows stay pending on failure (at-least-once; EventId dedups)."""
    rows = conn.execute(
        text("""SELECT id, payload FROM outbox WHERE topic = 'siem' AND dispatched_at IS NULL
                ORDER BY id LIMIT :n FOR UPDATE SKIP LOCKED"""),
        {"n": limit},
    ).all()
    if not rows:
        return 0, None
    try:
        client.send([dict(r.payload) for r in rows])
    except SentinelError as e:
        return 0, str(e)
    conn.execute(text("UPDATE outbox SET dispatched_at = now() WHERE id = ANY(:ids)"), {"ids": [r.id for r in rows]})
    return len(rows), None
