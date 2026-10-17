# SPDX-License-Identifier: Apache-2.0
"""Score open findings with the contextual risk model and publish the application's vulnerability posture.

The posture snapshot is platform-produced evidence (`vuln.posture`, C3): it is what the outcome controls
(ASC-VUL-01/02/03, ASC-ARC-03) evaluate. A new record is written only when the posture changed; otherwise the
existing one is re-confirmed (validity event), keeping the ledger proportional.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.domain.risk import RiskModel
from aap.store import config_store, evidence_store, findings_store, registry

OPEN = findings_store.OPEN_STATUSES


def _context(
    app: Mapping[str, Any], f: Mapping[str, Any], vuln: Mapping[str, Any] | None, component_scope: str | None
) -> dict[str, Any]:
    profile = app["profile"] or {}
    loc = f["location"] or {}
    ctx: dict[str, Any] = {
        "app": {
            "tier": app["tier_rank"],
            "exposure": app["exposure"],
            "data_classification": app["data_classification"],
            "personal_data": app["personal_data"],
            "privileged_integration": (profile.get("classification") or {}).get("privileged_integration"),
        },
        "finding": {
            "type": f["finding_type"],
            "tool_severity": f["tool_severity"],
            "confirmed_dynamically": bool(loc.get("confirmed_dynamically")),
            "requires_auth": loc.get("requires_auth"),
            "secret_validity": loc.get("validity"),
            "reachability": loc.get("reachability"),
            "cvss_exploitability": loc.get("cvss_exploitability"),
            "compensating_control_approved": bool(loc.get("compensating_control_approved")),
        },
    }
    if vuln is not None:
        ctx["vuln"] = {
            "in_cisa_kev": vuln["in_kev"],
            "exploit_public": vuln["exploit_public"],
            "epss_percentile": float(vuln["epss_percentile"]) if vuln["epss_percentile"] is not None else None,
        }
    if component_scope:
        ctx["component"] = {"scope": component_scope}
    return ctx


def score_application(conn: Connection, bundle: ConfigBundle, application_id: str) -> int:
    """Re-score open findings; record an assessment only when the result changed. Returns assessments written."""
    app = registry.application_context(conn, application_id)
    if app is None or app["tier_rank"] is None:
        return 0
    cfg = config_store.active(conn)
    model_doc = bundle.doc("risk_model")
    model = RiskModel(model_doc)
    written = 0
    for f in findings_store.for_application(conn, application_id):
        if f["status"] not in OPEN:
            continue
        vuln = (
            conn.execute(text("SELECT * FROM vulnerabilities WHERE id = :v"), {"v": f["vulnerability_id"]})
            .mappings()
            .first()
            if f["vulnerability_id"]
            else None
        )
        scope = (f["location"] or {}).get("component_scope")
        result = model.score(_context(app, f, vuln, scope))
        current = (
            conn.execute(
                text("SELECT priority, score, explanation FROM finding_risk_assessments WHERE id = :r"),
                {"r": f["risk_assessment_id"]},
            ).first()
            if f["risk_assessment_id"]
            else None
        )
        if current and (current.priority, current.score, current.explanation) == (
            result.priority,
            result.score,
            result.explanation,
        ):
            continue
        factor = 0.5 if f["finding_type"] == "exception_expired" else 1.0
        findings_store.record_risk(conn, str(f["id"]), result, cfg.ids["risk_model"], model_doc, factor)
        written += 1
    findings_store.mark_sla_breaches(conn, datetime.now(UTC))
    return written


def publish_posture(conn: Connection, application_id: str, now: datetime) -> str:
    rows = findings_store.for_application(conn, application_id)
    open_rows = [r for r in rows if r["status"] in OPEN]
    summary = {
        "open": len(open_rows),
        "by_priority": dict(Counter(r["priority"] or "unscored" for r in open_rows)),
        "sla_breached": sum(1 for r in open_rows if r["sla_breached"]),
        "untriaged_overdue": sum(
            1 for r in open_rows if r["status"] == "new" and r["triage_due_at"] and r["triage_due_at"] < now
        ),
        "expired_exceptions_open": sum(1 for r in open_rows if r["finding_type"] == "exception_expired"),
    }
    latest = conn.execute(
        text("""SELECT e.evidence_id, e.summary FROM evidence e JOIN evidence_current_state s USING (evidence_id)
                WHERE e.application_id = :a AND e.evidence_type = 'vuln.posture' AND s.state IN ('active', 'expiring')
                ORDER BY e.observed_at DESC LIMIT 1"""),
        {"a": application_id},
    ).first()
    if latest and latest.summary == evidence_store.normalise_summary(summary):
        evidence_store.record_validity(conn, latest.evidence_id, "active", "reconfirmed")
        return str(latest.evidence_id)
    app = registry.application_context(conn, application_id)
    assert app is not None
    return str(
        evidence_store.insert_evidence(
            conn,
            evidence_store.NewEvidence(
                evidence_type="vuln.posture",
                application_id=application_id,
                scope_type="application",
                scope_ref=str(app["app_key"]),
                subject={"application": str(app["app_key"])},
                producer_type="platform_connector",
                producer_ref="connector:risk-engine",
                observed_at=now,
                result="observed",
                confidence="C3",
                summary=summary,
                confidence_reasons=["platform_derived"],
            ),
        )
    )
