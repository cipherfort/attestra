# SPDX-License-Identifier: Apache-2.0
"""Load governed configuration into the database (E05-F02-S01).

Idempotent: the same content (by SHA-256) loads once; activation is explicit and one version per kind is active.
Controls, their applicability and their SAMM mappings are materialised for the catalogue version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.ids import uuid7

KINDS = {
    "control_catalogue": "control_catalogue",
    "risk_model": "risk_model",
    "classification": "classification",
    "evidence_types": "evidence_types",
    "licence_policy": "licence_policy",
    "trusted_producers": "trusted_producers",
    "maturity_methodology": "maturity_methodology",
    "samm_targets": "samm_targets",
}


@dataclass(frozen=True)
class ActiveConfig:
    ids: dict[str, str]  # kind → config_versions.id
    controls: dict[str, str]  # control key → controls.id (active catalogue)
    samm_items: dict[str, str]  # SAMM short id (stream/practice/function) → framework_items.id


def load(conn: Connection, bundle: ConfigBundle, git_sha: str = "local") -> ActiveConfig:
    ids: dict[str, str] = {}
    for kind, doc_kind in KINDS.items():
        doc = bundle.documents[doc_kind]
        version = f"{doc.version}+{doc.sha256[:12]}"
        row = conn.execute(
            text("SELECT id FROM config_versions WHERE kind = :k AND version = :v"), {"k": kind, "v": version}
        ).first()
        if row is None:
            row = conn.execute(
                text(
                    "INSERT INTO config_versions (id, kind, version, git_sha, content_sha256, content) "
                    "VALUES (:id, :k, :v, :git, :sha, CAST(:content AS jsonb)) RETURNING id"
                ),
                {
                    "id": uuid7(),
                    "k": kind,
                    "v": version,
                    "git": git_sha,
                    "sha": bytes.fromhex(doc.sha256),
                    "content": json.dumps(doc.content, default=str),
                },
            ).one()
        ids[kind] = str(row.id)
        conn.execute(
            text(
                "UPDATE config_versions SET active = (id = :id) WHERE kind = :k AND active IS DISTINCT FROM (id = :id)"
            ),
            {"id": row.id, "k": kind},
        )
    samm_items = _load_samm(conn, bundle)
    controls = _load_controls(conn, bundle, ids["control_catalogue"], samm_items)
    return ActiveConfig(ids, controls, samm_items)


def _load_samm(conn: Connection, bundle: ConfigBundle) -> dict[str, str]:
    samm = bundle.doc("samm")
    fw = conn.execute(
        text("SELECT id FROM frameworks WHERE framework_key = 'samm' AND version = :v"), {"v": str(samm["version"])}
    ).first()
    if fw is None:
        fw = conn.execute(
            text(
                "INSERT INTO frameworks (id, framework_key, version, source_url, content_sha256) "
                "VALUES (:id, 'samm', :v, :src, :sha) RETURNING id"
            ),
            {
                "id": uuid7(),
                "v": str(samm["version"]),
                "src": samm["source"],
                "sha": bytes.fromhex(bundle.documents["samm"].sha256),
            },
        ).one()
    items: dict[str, str] = {}

    def upsert(key: str, parent: str | None, item_type: str, title: str) -> str:
        row = conn.execute(
            text("""INSERT INTO framework_items (id, framework_id, item_key, parent_id, item_type, title)
                    VALUES (:id, :fw, :key, :parent, :type, :title)
                    ON CONFLICT (framework_id, item_key) DO UPDATE SET title = EXCLUDED.title RETURNING id"""),
            {"id": uuid7(), "fw": fw.id, "key": key, "parent": parent, "type": item_type, "title": title},
        ).one()
        items[key] = str(row.id)
        return str(row.id)

    for bf in samm["business_functions"]:
        bf_id = upsert(bf["id"], None, "business_function", bf["name"])
        for p in bf["practices"]:
            p_id = upsert(p["id"], bf_id, "practice", p["name"])
            for s in p["streams"]:
                upsert(s["id"], p_id, "stream", s["name"])
    return items


def _load_controls(
    conn: Connection, bundle: ConfigBundle, catalogue_id: str, samm_items: dict[str, str]
) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in bundle.catalogue["controls"]:
        row = conn.execute(
            text("""INSERT INTO controls (id, catalogue_version_id, control_key, title, domain, objective_type,
                      assessment_mode, definition)
                    VALUES (:id, :cat, :key, :title, :domain, :otype, :mode, CAST(:def AS jsonb))
                    ON CONFLICT (catalogue_version_id, control_key) DO UPDATE SET title = EXCLUDED.title RETURNING id"""),
            {
                "id": uuid7(),
                "cat": catalogue_id,
                "key": c["id"],
                "title": c["title"],
                "domain": c["domain"],
                "otype": c["objective_type"],
                "mode": c["assessment"]["mode"],
                "def": json.dumps(c, default=str),
            },
        ).one()
        out[c["id"]] = str(row.id)
        for tier, level in c["applicability"]["tiers"].items():
            conn.execute(
                text("""INSERT INTO control_applicability (control_id, tier_rank, requirement, conditions)
                        VALUES (:c, :t, :r, :cond) ON CONFLICT DO NOTHING"""),
                {"c": row.id, "t": int(tier), "r": level, "cond": c["applicability"].get("conditions", [])},
            )
        for m in c["mappings"].get("samm", []):
            conn.execute(
                text("""INSERT INTO control_framework_mappings (control_id, framework_item_id, level)
                        VALUES (:c, :i, :l) ON CONFLICT DO NOTHING"""),
                {"c": row.id, "i": samm_items[m["stream"]], "l": int(m["level"])},
            )
    return out


def active(conn: Connection) -> ActiveConfig:
    ids = {r.kind: str(r.id) for r in conn.execute(text("SELECT id, kind FROM config_versions WHERE active"))}
    if "control_catalogue" not in ids:
        raise RuntimeError("no active configuration: run `aap config load`")
    controls = {
        r.control_key: str(r.id)
        for r in conn.execute(
            text("SELECT id, control_key FROM controls WHERE catalogue_version_id = :c"),
            {"c": ids["control_catalogue"]},
        )
    }
    samm = {
        r.item_key: str(r.id)
        for r in conn.execute(
            text(
                "SELECT fi.id, fi.item_key FROM framework_items fi JOIN frameworks f ON f.id = fi.framework_id "
                "WHERE f.framework_key = 'samm'"
            )
        )
    }
    return ActiveConfig(ids, controls, samm)
