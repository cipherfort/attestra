# SPDX-License-Identifier: Apache-2.0
"""Built-in vulnerability intelligence (no Dependency-Track needed):

osv_sync   every component in a current SBOM → OSV querybatch (OSV does the ecosystem-correct version matching)
           → advisories upserted, component ↔ advisory links (source 'osv'), dependency findings raised; links for
           advisories OSV no longer returns (withdrawn) are removed
kev_sync   CISA Known Exploited Vulnerabilities → vulnerabilities.in_kev / kev_added_at (refuses partial catalogues)
epss_sync  FIRST EPSS → epss_score / epss_percentile / epss_date for the CVEs the platform holds

Every change that can move a finding's priority queues the affected applications for re-scoring.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aap.domain.cvss import CvssError, base_score
from aap.domain.fingerprints import purl_without_version
from aap.services.vuln_service import raise_dependency_findings
from aap.store import jobs, supply_chain


@dataclass
class FeedReport:
    queried: int = 0
    advisories_fetched: int = 0
    links_added: int = 0
    links_removed: int = 0
    findings_raised: int = 0
    changed: int = 0
    errors: list[str] = field(default_factory=list)


def osv_to_advisory(v: Mapping[str, Any]) -> dict[str, Any]:
    ids = [v["id"], *(v.get("aliases") or [])]
    cves = [i for i in ids if i.startswith("CVE-")]
    key = cves[0] if cves else v["id"]
    adv: dict[str, Any] = {
        "id": key,
        "aliases": sorted({i for i in ids if i != key}),
        "title": (v.get("summary") or (v.get("details") or "")[:200] or None),
        "cwe": sorted(
            {int(c.split("-")[1]) for c in (v.get("database_specific") or {}).get("cwe_ids") or [] if c[4:].isdigit()}
        ),
        "is_malicious": v["id"].startswith("MAL-"),
        "source": "osv",
    }
    for sev in v.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            with contextlib.suppress(CvssError):  # an unparsable vector leaves the score empty (scored as unknown)
                adv["cvss_v3_score"], adv["cvss_v3_vector"] = base_score(sev["score"]), sev["score"]
    return adv


def fixed_versions(v: Mapping[str, Any], purl: str) -> list[str]:
    base = purl_without_version(purl)
    affected = v.get("affected") or []
    mine = [a for a in affected if purl_without_version((a.get("package") or {}).get("purl", "") or "") == base]
    pool = mine or (affected if len(affected) == 1 else [])
    return sorted(
        {e["fixed"] for a in pool for r in a.get("ranges") or [] for e in r.get("events") or [] if "fixed" in e}
    )


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _existing(conn: Connection, ids: Iterable[str]) -> dict[str, Any]:
    """OSV id or alias → (vulnerability id, vuln_key, modified_at) for advisories already held."""
    ids = list(ids)
    rows = conn.execute(
        text("""SELECT id, vuln_key, aliases, modified_at FROM vulnerabilities
                WHERE vuln_key = ANY(:ids) OR aliases && CAST(:ids AS text[])"""),
        {"ids": ids},
    ).all()
    out: dict[str, Any] = {}
    for r in rows:
        for i in [r.vuln_key, *r.aliases]:
            out[i] = r
    return out


def osv_sync(conn: Connection, osv: Any, now: datetime) -> FeedReport:
    rep = FeedReport()
    comps = conn.execute(
        text("""SELECT DISTINCT c.id, c.purl FROM components c
                JOIN sbom_components sc ON sc.component_id = c.id JOIN sboms s ON s.id = sc.sbom_id AND s.is_current""")
    ).all()
    if not comps:
        return rep
    by_purl = {c.purl: str(c.id) for c in comps}
    matches = osv.querybatch(list(by_purl))
    rep.queried = len(by_purl)
    current = {
        (str(r.component_id), str(r.vulnerability_id))
        for r in conn.execute(
            text("SELECT component_id, vulnerability_id FROM component_vulnerabilities WHERE source = 'osv'")
        )
    }
    all_ids = {vid for found in matches.values() for vid in found}
    held = _existing(conn, all_ids)
    details: dict[str, Mapping[str, Any]] = {}
    vuln_of: dict[str, str] = {}
    for vid in sorted(all_ids):
        modified = max(m for found in matches.values() for i, m in found.items() if i == vid)
        known = held.get(vid)
        changed = _ts(modified)
        needs_detail = (
            known is None or known.modified_at is None or (changed is not None and changed > known.modified_at)
        )
        new_pair = known is not None and any(
            (by_purl[p], str(known.id)) not in current for p, found in matches.items() if vid in found
        )
        if known is not None and not (needs_detail or new_pair):  # known is None implies needs_detail
            vuln_of[vid] = str(known.id)
            continue
        try:
            v = osv.vuln(vid)
        except Exception as e:  # one advisory failing must not hide the rest: recorded as an error (a gap)
            rep.errors.append(f"{vid}: {e}"[:200])
            continue
        rep.advisories_fetched += 1
        details[vid] = v
        adv = osv_to_advisory(v)
        if known is not None:
            adv["id"] = known.vuln_key  # keep the key the platform already uses (e.g. from Dependency-Track)
        vid_uuid = supply_chain.upsert_vulnerability(conn, adv)
        conn.execute(
            text("""UPDATE vulnerabilities SET modified_at = CAST(:m AS timestamptz), published_at = COALESCE(
                      CAST(:p AS timestamptz), published_at), description = COALESCE(:d, description),
                      is_malicious = is_malicious OR :mal WHERE id = :id"""),
            {
                "m": v.get("modified"),
                "p": v.get("published"),
                "d": (v.get("details") or None),
                "mal": adv["is_malicious"],
                "id": vid_uuid,
            },
        )
        vuln_of[vid] = vid_uuid

    seen: set[tuple[str, str]] = set()
    touched: set[str] = set()
    for purl, found in matches.items():
        comp = by_purl[purl]
        for vid in found:
            if vid not in vuln_of:
                continue
            pair = (comp, vuln_of[vid])
            seen.add(pair)
            if pair in current:
                continue
            fixed = fixed_versions(details[vid], purl) if vid in details else []
            conn.execute(
                text("""INSERT INTO component_vulnerabilities (component_id, vulnerability_id, fixed_versions, source)
                        VALUES (:c, :v, :f, 'osv') ON CONFLICT DO NOTHING"""),
                {"c": comp, "v": pair[1], "f": fixed},
            )
            rep.links_added += 1
            touched.add(pair[1])
    # advisories OSV no longer reports for a component we queried (withdrawn or corrected)
    queried = set(by_purl.values())
    for comp, vuln in current - seen:
        if comp in queried and not rep.errors:  # an advisory we failed to fetch is not evidence of withdrawal
            conn.execute(
                text("""DELETE FROM component_vulnerabilities
                        WHERE component_id = :c AND vulnerability_id = :v AND source = 'osv'"""),
                {"c": comp, "v": vuln},
            )
            rep.links_removed += 1
    for vuln in sorted(touched):
        rep.findings_raised += raise_dependency_findings(conn, vuln, now)
    _requeue(conn, touched)
    return rep


def kev_sync(conn: Connection, kev: Any) -> FeedReport:
    rep = FeedReport()
    _, entries = kev.catalogue()
    cves, added = [e.cve for e in entries], [e.added for e in entries]
    flagged = conn.execute(
        text("""UPDATE vulnerabilities v SET in_kev = true, kev_added_at = k.added, exploit_public = true
                FROM unnest(CAST(:cves AS text[]), CAST(:added AS date[])) AS k(cve, added)
                WHERE (v.vuln_key = k.cve OR k.cve = ANY(v.aliases))
                  AND (NOT v.in_kev OR v.kev_added_at IS DISTINCT FROM k.added)
                RETURNING v.id"""),
        {"cves": cves, "added": added},
    ).all()
    cleared = conn.execute(
        text("""UPDATE vulnerabilities SET in_kev = false
                WHERE in_kev AND NOT (vuln_key = ANY(CAST(:cves AS text[])) OR aliases && CAST(:cves AS text[]))
                RETURNING id"""),
        {"cves": cves},
    ).all()
    changed = {str(r.id) for r in [*flagged, *cleared]}
    rep.queried, rep.changed = len(entries), len(changed)
    _requeue(conn, changed)
    return rep


def epss_sync(conn: Connection, epss: Any) -> FeedReport:
    rep = FeedReport()
    rows = conn.execute(text("SELECT id, vuln_key, aliases FROM vulnerabilities")).all()
    cve_to_ids: dict[str, set[str]] = {}
    for r in rows:
        for i in [r.vuln_key, *r.aliases]:
            if i.startswith("CVE-"):
                cve_to_ids.setdefault(i, set()).add(str(r.id))
    if not cve_to_ids:
        return rep
    rep.queried = len(cve_to_ids)
    changed: set[str] = set()
    for s in epss.scores(cve_to_ids):
        for vid in cve_to_ids.get(s.cve, ()):
            row = conn.execute(
                text("""UPDATE vulnerabilities SET epss_score = :e, epss_percentile = :p, epss_date = :d
                        WHERE id = :id AND (epss_date IS DISTINCT FROM :d OR epss_score IS DISTINCT FROM :e)
                        RETURNING id"""),
                {"e": s.epss, "p": s.percentile, "d": s.day, "id": vid},
            ).first()
            if row:
                changed.add(vid)
    rep.changed = len(changed)
    _requeue(conn, changed)
    return rep


def _requeue(conn: Connection, vulnerability_ids: Iterable[str]) -> None:
    """Applications with open findings on these advisories are re-scored (risk) and re-evaluated."""
    ids = list(vulnerability_ids)
    if not ids:
        return
    for row in conn.execute(
        text("""SELECT DISTINCT application_id FROM findings
                WHERE vulnerability_id = ANY(CAST(:v AS uuid[])) AND status NOT IN ('closed', 'false_positive')"""),
        {"v": ids},
    ):
        jobs.enqueue(
            conn, "evaluate", {"application_id": str(row.application_id)}, dedup_key=f"evaluate:{row.application_id}"
        )
