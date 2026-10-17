# SPDX-License-Identifier: Apache-2.0
"""End-of-life check (ASC-ARC-02): current SBOM components → endoflife.date cycles → `sbom.eol` evidence per
application, recorded with the date of the data used. Derived evidence: its confidence is that of the weakest SBOM
it was derived from, so a derived record can never be stronger than its inputs."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aap.connectors.eol import match_cycle
from aap.domain.evidence import AUTOMATED_ORDER
from aap.domain.fingerprints import purl_without_version
from aap.store import evidence_store, jobs


def eol_sync(conn: Connection, client: Any, policy: dict[str, Any], now: datetime) -> dict[str, Any]:
    products: dict[str, str | None] = policy.get("products") or {}
    warn = timedelta(days=int(policy.get("warn_days", 180)))
    rows = conn.execute(
        text("""SELECT s.application_id, a.app_key, c.purl, c.version, e.confidence
                FROM sboms s JOIN applications a ON a.id = s.application_id
                JOIN sbom_components sc ON sc.sbom_id = s.id JOIN components c ON c.id = sc.component_id
                JOIN evidence e ON e.evidence_id = s.evidence_id
                WHERE s.is_current AND s.application_id IS NOT NULL""")
    ).all()
    per_app: dict[str, list[Any]] = defaultdict(list)
    for r in rows:
        per_app[str(r.application_id)].append(r)
    wanted = sorted({p for r in rows if (p := products.get(purl_without_version(r.purl)))})
    cycles, errors = {}, []
    for product in wanted:
        try:
            cycles[product] = client.cycles(product)
        except Exception as e:  # a product we could not read is reported, and its components count as unchecked
            errors.append(f"{product}: {e}"[:200])
    today = now.date()
    written = 0
    for app_id, comps in per_app.items():
        eol, soon, checked = [], [], 0
        for r in comps:
            product = products.get(purl_without_version(r.purl))
            if not product or product not in cycles:
                continue
            checked += 1
            c = match_cycle(r.version, cycles[product])
            if c is None:
                continue
            item = {"purl": r.purl, "product": product, "cycle": c.cycle, "eol": c.eol.isoformat() if c.eol else "yes"}
            if c.eol_now or (c.eol is not None and c.eol <= today):
                eol.append(item)
            elif c.eol is not None and c.eol <= today + warn:
                soon.append(item)
        confidences = [r.confidence for r in comps if r.confidence in AUTOMATED_ORDER]
        confidence = min(confidences, key=AUTOMATED_ORDER.index) if confidences else "C1"
        evidence_store.insert_evidence(
            conn,
            evidence_store.NewEvidence(
                evidence_type="sbom.eol",
                application_id=app_id,
                scope_type="application",
                scope_ref=comps[0].app_key,
                subject={"source": "endoflife.date", "products": wanted},
                producer_type="platform_connector",
                producer_ref="connector:endoflife",
                observed_at=now,
                result="fail" if eol else "pass",
                confidence=confidence,
                summary={
                    "snapshot": today.isoformat(),
                    "components": len({r.purl for r in comps}),
                    "checked": checked,
                    "eol": sorted(eol, key=lambda x: x["purl"])[:50],
                    "eol_soon": sorted(soon, key=lambda x: x["purl"])[:50],
                    "unreadable_products": len(errors),
                },
                confidence_reasons=["derived_from_sbom"],
            ),
        )
        jobs.enqueue(conn, "evaluate", {"application_id": app_id}, dedup_key=f"evaluate:{app_id}")
        written += 1
    return {"applications": written, "products": len(cycles), "errors": errors}
