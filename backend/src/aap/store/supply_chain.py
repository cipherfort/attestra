# SPDX-License-Identifier: Apache-2.0
"""SBOM inventory, vulnerability intelligence and the CVE-impact query (ADR-009, E10).

In production, Dependency-Track performs continuous component ↔ advisory matching and the platform syncs the
matches (connector DESIGNED). `match_advisory` is the in-platform matcher used in development and by the demo:
exact version lists or [introduced, fixed) ranges on dotted numeric versions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from aap.domain.fingerprints import purl_without_version
from aap.domain.sbom import assess_quality, walk_components
from aap.ids import uuid7


@dataclass(frozen=True)
class SbomStats:
    sbom_id: str
    component_count: int
    purl_coverage_pct: float
    quality_ok: bool
    problems: tuple[str, ...]


def licence_of(c: Mapping[str, Any]) -> str | None:
    exprs = []
    for lic in c.get("licenses") or []:
        if "expression" in lic:
            exprs.append(lic["expression"])
        elif "license" in lic:
            exprs.append(lic["license"].get("id") or lic["license"].get("name") or "NOASSERTION")
    return " AND ".join(exprs) if exprs else None


def ingest_cyclonedx(
    conn: Connection,
    *,
    application_id: str,
    repository_id: str | None,
    scope_key: str,
    commit_sha: str | None,
    bom: Mapping[str, Any],
    evidence_id: str,
    generated_at: Any,
) -> SbomStats:
    count, pct, problems = assess_quality(bom)
    conn.execute(text("UPDATE sboms SET is_current = false WHERE scope_key = :k AND is_current"), {"k": scope_key})
    sbom_id = str(uuid7())
    conn.execute(
        text("""INSERT INTO sboms (id, application_id, repository_id, scope_key, commit_sha, format, spec_version,
                  serial_number, component_count, purl_coverage_pct, evidence_id, is_current, generated_at)
                VALUES (:id, :a, :r, :k, :sha, 'cyclonedx', :spec, :serial, :n, :pct, :ev, true, :gen)"""),
        {
            "id": sbom_id,
            "a": application_id,
            "r": repository_id,
            "k": scope_key,
            "sha": commit_sha,
            "spec": str(bom.get("specVersion", "?")),
            "serial": bom.get("serialNumber"),
            "n": count,
            "pct": pct,
            "ev": evidence_id,
            "gen": generated_at,
        },
    )
    for c in walk_components(bom.get("components") or []):
        purl = c.get("purl")
        if not purl:
            continue
        m = re.match(r"pkg:([^/]+)/", purl)
        comp = conn.execute(
            text("""INSERT INTO components (id, purl, ecosystem, namespace, name, version, licence_expression)
                    VALUES (:id, :purl, :eco, :ns, :name, :ver, :lic)
                    ON CONFLICT (purl) DO UPDATE SET licence_expression = COALESCE(EXCLUDED.licence_expression,
                      components.licence_expression) RETURNING id"""),
            {
                "id": uuid7(),
                "purl": purl,
                "eco": m.group(1) if m else "unknown",
                "ns": c.get("group"),
                "name": c.get("name") or purl,
                "ver": c.get("version") or "",
                "lic": licence_of(c),
            },
        ).one()
        scope = {"required": "required", "optional": "optional", "excluded": "development"}.get(
            c.get("scope", ""), "unknown"
        )
        conn.execute(
            text(
                "INSERT INTO sbom_components (sbom_id, component_id, scope) VALUES (:s, :c, :scope) ON CONFLICT DO NOTHING"
            ),
            {"s": sbom_id, "c": comp.id, "scope": scope},
        )
    if not problems and count > 0:  # an empty or broken SBOM proves nothing: unknown is never closed as fixed
        from aap.store import findings_store

        findings_store.close_dependencies_absent(
            conn, scope_ref=scope_key, sbom_id=sbom_id, evidence_id=evidence_id, at=generated_at
        )
    return SbomStats(sbom_id, count, pct, not problems, tuple(problems))


def upsert_vulnerability(conn: Connection, adv: Mapping[str, Any]) -> str:
    row = conn.execute(
        text("""INSERT INTO vulnerabilities (id, vuln_key, aliases, title, cwe_ids, cvss_v3_score, cvss_v3_vector,
                  epss_score, epss_percentile, epss_date, in_kev, kev_added_at, exploit_public, is_malicious)
                VALUES (:id, :key, :aliases, :title, :cwe, :cvss, :vector, :epss, :pct, :edate, COALESCE(:kev, false),
                        :kevd, :exp, :mal)
                ON CONFLICT (vuln_key) DO UPDATE SET
                  -- a source that does not supply a field (e.g. Dependency-Track has no KEV) never erases it
                  aliases = ARRAY(SELECT DISTINCT unnest(vulnerabilities.aliases || EXCLUDED.aliases)),
                  title = COALESCE(vulnerabilities.title, EXCLUDED.title),
                  cvss_v3_score = COALESCE(EXCLUDED.cvss_v3_score, vulnerabilities.cvss_v3_score),
                  cvss_v3_vector = COALESCE(EXCLUDED.cvss_v3_vector, vulnerabilities.cvss_v3_vector),
                  epss_score = COALESCE(EXCLUDED.epss_score, vulnerabilities.epss_score),
                  epss_percentile = COALESCE(EXCLUDED.epss_percentile, vulnerabilities.epss_percentile),
                  epss_date = COALESCE(EXCLUDED.epss_date, vulnerabilities.epss_date),
                  in_kev = CASE WHEN CAST(:kev AS boolean) IS NULL THEN vulnerabilities.in_kev ELSE EXCLUDED.in_kev END,
                  kev_added_at = COALESCE(EXCLUDED.kev_added_at, vulnerabilities.kev_added_at),
                  synced_at = now()
                RETURNING id"""),
        {
            "id": uuid7(),
            "key": adv["id"],
            "aliases": adv.get("aliases", []),
            "title": adv.get("title"),
            "cwe": adv.get("cwe", []),
            "cvss": adv.get("cvss_v3_score"),
            "vector": adv.get("cvss_v3_vector"),
            "epss": adv.get("epss_score"),
            "pct": adv.get("epss_percentile"),
            "edate": adv.get("epss_date"),
            "kev": None if "in_kev" not in adv else bool(adv["in_kev"]),
            "kevd": adv.get("kev_added_at"),
            "exp": bool(adv.get("exploit_public")),
            "mal": bool(adv.get("is_malicious")),
        },
    ).one()
    return str(row.id)


def _version_tuple(v: str) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def version_affected(version: str, affected: Mapping[str, Any]) -> bool:
    if version in (affected.get("versions") or []):
        return True
    v = _version_tuple(version)
    for rng in affected.get("ranges") or []:
        lo = _version_tuple(rng.get("introduced", "0"))
        hi = _version_tuple(rng["fixed"]) if rng.get("fixed") else None
        if v is not None and lo is not None and v >= lo and (hi is None or v < hi):
            return True
    return False


def match_advisory(conn: Connection, adv: Mapping[str, Any], vulnerability_id: str) -> list[str]:
    """Link the advisory to every inventory component it affects. Returns matched component ids."""
    matched = []
    for affected in adv.get("affected", []):
        base = purl_without_version(affected["purl"])
        for comp in conn.execute(
            text("SELECT id, purl, version FROM components WHERE purl LIKE :p"), {"p": base.replace("%", r"\%") + "@%"}
        ):
            if purl_without_version(comp.purl) == base and version_affected(comp.version, affected):
                conn.execute(
                    text("""INSERT INTO component_vulnerabilities (component_id, vulnerability_id, fixed_versions, source)
                            VALUES (:c, :v, :fixed, :src) ON CONFLICT DO NOTHING"""),
                    {
                        "c": comp.id,
                        "v": vulnerability_id,
                        "src": adv.get("source", "platform"),  # callers name the matcher; never guess a feed
                        "fixed": [r["fixed"] for r in affected.get("ranges", []) if r.get("fixed")],
                    },
                )
                matched.append(str(comp.id))
    return matched


def affected_applications(conn: Connection, vuln_ref: str) -> dict[str, Any] | None:
    """Three honest sets (ADR-009): affected · possibly affected (no / stale / inconclusive SBOM) · not affected.
    Runs under the caller's RLS scope, so each caller sees only applications they may see."""
    vuln = (
        conn.execute(
            text("SELECT * FROM vulnerabilities WHERE vuln_key = :r OR :r = ANY(aliases) LIMIT 1"), {"r": vuln_ref}
        )
        .mappings()
        .first()
    )
    if vuln is None:
        return None
    apps = (
        conn.execute(
            text("SELECT id, app_key, name, tier_rank, exposure FROM applications WHERE lifecycle <> 'retired'")
        )
        .mappings()
        .all()
    )
    sbom_rows = (
        conn.execute(
            text("""SELECT s.application_id, s.id AS sbom_id, s.component_count, s.purl_coverage_pct,
                       COALESCE(es.state::text, 'expired') AS freshness
                FROM sboms s LEFT JOIN evidence_current_state es ON es.evidence_id = s.evidence_id
                WHERE s.is_current"""),
        )
        .mappings()
        .all()
    )
    hits = (
        conn.execute(
            text("""SELECT s.application_id, c.purl, cv.fixed_versions, sc.scope
                FROM component_vulnerabilities cv
                JOIN sbom_components sc ON sc.component_id = cv.component_id
                JOIN sboms s ON s.id = sc.sbom_id AND s.is_current
                JOIN components c ON c.id = cv.component_id
                WHERE cv.vulnerability_id = :v"""),
            {"v": vuln["id"]},
        )
        .mappings()
        .all()
    )
    by_app_hits: dict[str, list[dict[str, Any]]] = {}
    for h in hits:
        by_app_hits.setdefault(str(h["application_id"]), []).append(
            {"purl": h["purl"], "fixed_versions": list(h["fixed_versions"]), "scope": h["scope"]}
        )
    sbom_state: dict[str, str] = {}
    for s in sbom_rows:
        ok = s["freshness"] in ("active", "expiring") and s["component_count"] > 0
        prev = sbom_state.get(str(s["application_id"]))
        sbom_state[str(s["application_id"])] = "current" if ok or prev == "current" else "stale_sbom"

    affected: list[dict[str, Any]] = []
    possibly: list[dict[str, Any]] = []
    not_affected = 0
    for a in apps:
        aid = str(a["id"])
        summary = {
            "id": aid,
            "app_key": a["app_key"],
            "name": a["name"],
            "tier": a["tier_rank"],
            "exposure": a["exposure"],
        }
        if aid in by_app_hits:
            affected.append({"application": summary, "components": by_app_hits[aid]})
        elif sbom_state.get(aid) == "current":
            not_affected += 1
        else:
            possibly.append({"application": summary, "reason": sbom_state.get(aid, "no_sbom")})
    affected.sort(key=lambda x: (x["application"]["tier"] or 9, x["application"]["name"]))
    return {
        "vulnerability": dict(vuln),
        "affected": affected,
        "possibly_affected": possibly,
        "not_affected_count": not_affected,
    }
