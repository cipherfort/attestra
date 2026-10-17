# SPDX-License-Identifier: Apache-2.0
"""Administration: the organization tree, who belongs where, and scoped role grants (permission org.admin).

Runs as the narrow `aap_admin` database role (migration 0009). Guard rails:
* unit types and their order come from config/organization.yaml: a unit's parent is exactly one level above it;
* nobody grants or revokes roles for themselves (segregation of duties);
* `platform_admin` is never granted here: it comes from the identity provider (PIM-eligible app role) only;
* org-wide roles take no unit scope; scoped roles (champion, unit_lead, app_owner, engineer) need one;
* every change is written to the hash-chained audit log by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, text

from aap.config import ConfigBundle
from aap.ids import uuid7

SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
GRANTABLE = frozenset(
    {
        "security_leadership",
        "appsec_engineer",
        "governance_analyst",
        "unit_lead",
        "app_owner",
        "engineer",
        "champion",
        "auditor",
        "executive",
    }
)
SCOPED = frozenset({"unit_lead", "app_owner", "engineer", "champion"})


class AdminError(ValueError):
    def __init__(self, problem: str, status: int = 422):
        super().__init__(problem)
        self.problem, self.status = problem, status


def levels(bundle: ConfigBundle) -> list[str]:
    return [str(lvl["type"]) for lvl in bundle.doc("organization")["levels"]]


def _unit(conn: Connection, slug: str) -> Mapping[str, Any]:
    row = conn.execute(text("SELECT * FROM org_units WHERE slug = :s"), {"s": slug}).mappings().first()
    if row is None:
        raise AdminError(f"no unit {slug!r}", 404)
    return row


def tree(conn: Connection) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text("""SELECT o.id, o.slug, o.name, o.unit_type, p.slug AS parent, o.scm_group, o.idp_group_id,
                  (SELECT count(*) FROM org_unit_members m WHERE m.org_unit_id = o.id) AS members,
                  (SELECT count(*) FROM applications a WHERE a.org_unit_id = o.id) AS applications
                FROM org_units o LEFT JOIN org_units p ON p.id = o.parent_id ORDER BY o.unit_type, o.name""")
        )
        .mappings()
        .all()
    )
    return [dict(r) | {"id": str(r["id"])} for r in rows]


def create_unit(conn: Connection, bundle: ConfigBundle, *, slug: str, name: str, unit_type: str, parent: str) -> str:
    order = levels(bundle)
    if not SLUG.match(slug):
        raise AdminError("slug: lower-case letters, digits and hyphens, 3–64 characters")
    if unit_type not in order or order.index(unit_type) == 0:
        raise AdminError(f"unit_type must be one of {', '.join(order[1:])} (config/organization.yaml)")
    p = _unit(conn, parent)
    if p["unit_type"] != order[order.index(unit_type) - 1]:
        raise AdminError(
            f"a {unit_type} sits directly under a {order[order.index(unit_type) - 1]}, not a {p['unit_type']}"
        )
    if conn.execute(text("SELECT 1 FROM org_units WHERE slug = :s"), {"s": slug}).first():
        raise AdminError(f"unit {slug!r} already exists", 409)
    uid = uuid7()
    conn.execute(
        text("""INSERT INTO org_units (id, slug, name, unit_type, parent_id) VALUES (:id, :s, :n, :t, :p)"""),
        {"id": uid, "s": slug, "n": name.strip()[:200], "t": unit_type, "p": p["id"]},
    )
    return str(uid)


def update_unit(conn: Connection, slug: str, fields: Mapping[str, Any]) -> None:
    u = _unit(conn, slug)
    allowed = {k: v for k, v in fields.items() if k in ("name", "scm_group", "idp_group_id")}
    if not allowed:
        raise AdminError("nothing to change (name, scm_group, idp_group_id)")
    sets = ", ".join(f"{k} = :{k}" for k in allowed)
    conn.execute(text(f"UPDATE org_units SET {sets} WHERE id = :id"), {**allowed, "id": u["id"]})  # noqa: S608


def members(conn: Connection, slug: str) -> list[dict[str, Any]]:
    u = _unit(conn, slug)
    return [
        {"user_id": str(r.id), "display_name": r.display_name, "source": r.source}
        for r in conn.execute(
            text("""SELECT u.id, u.display_name, m.source FROM org_unit_members m JOIN users u ON u.id = m.user_id
                    WHERE m.org_unit_id = :o ORDER BY u.display_name"""),
            {"o": u["id"]},
        )
    ]


def set_member(conn: Connection, slug: str, user_id: str, present: bool) -> None:
    u = _unit(conn, slug)
    if conn.execute(text("SELECT 1 FROM users WHERE id::text = :u"), {"u": user_id}).first() is None:
        raise AdminError("no such user", 404)
    if present:
        conn.execute(
            text("""INSERT INTO org_unit_members (org_unit_id, user_id, source) VALUES (:o, CAST(:u AS uuid), 'manual')
                    ON CONFLICT DO NOTHING"""),
            {"o": u["id"], "u": user_id},
        )
    else:
        conn.execute(
            text("DELETE FROM org_unit_members WHERE org_unit_id = :o AND user_id::text = :u"),
            {"o": u["id"], "u": user_id},
        )


def grants(conn: Connection) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text("""SELECT r.id, r.principal_type, r.principal_id, r.role, o.slug AS org_unit, r.granted_at, r.expires_at,
                  u.display_name AS principal_name, g.display_name AS granted_by
                FROM role_assignments r LEFT JOIN org_units o ON o.id = r.scope_org_unit_id
                LEFT JOIN users u ON r.principal_type = 'user' AND u.id::text = r.principal_id
                LEFT JOIN users g ON g.id = r.granted_by ORDER BY r.role, principal_name""")
        )
        .mappings()
        .all()
    )
    return [dict(r) | {"id": str(r["id"])} for r in rows]


def grant(
    conn: Connection,
    *,
    actor: str,
    principal_type: str,
    principal_id: str,
    role: str,
    org_unit: str | None = None,
    expires_at: Any = None,
) -> str:
    if role not in GRANTABLE:
        raise AdminError(
            "platform_admin is assigned in the identity provider only"
            if role == "platform_admin"
            else f"unknown role {role!r}"
        )
    if principal_type not in ("user", "idp_group"):
        raise AdminError("principal_type must be user or idp_group")
    if principal_type == "user" and str(principal_id) == str(actor):
        raise AdminError("segregation of duties: you cannot grant roles to yourself", 403)
    if (
        principal_type == "user"
        and not conn.execute(text("SELECT 1 FROM users WHERE id::text = :u"), {"u": principal_id}).first()
    ):
        raise AdminError("no such user", 404)
    if role in SCOPED and not org_unit:
        raise AdminError(f"{role} is a scoped role: give the org unit it applies to")
    if role not in SCOPED and org_unit:
        raise AdminError(f"{role} is organization-wide: it takes no unit scope")
    unit_id = _unit(conn, org_unit)["id"] if org_unit else None
    dup = conn.execute(
        text("""SELECT 1 FROM role_assignments WHERE principal_type = :t AND principal_id = :p AND role = :r
                AND scope_org_unit_id IS NOT DISTINCT FROM CAST(:o AS uuid)"""),
        {"t": principal_type, "p": principal_id, "r": role, "o": str(unit_id) if unit_id else None},
    ).first()
    if dup:
        raise AdminError("that grant already exists", 409)
    gid = uuid7()
    conn.execute(
        text("""INSERT INTO role_assignments (id, principal_type, principal_id, role, scope_org_unit_id, granted_by,
                  expires_at) VALUES (:id, :t, :p, :r, :o, :by, :exp)"""),
        {"id": gid, "t": principal_type, "p": principal_id, "r": role, "o": unit_id, "by": actor, "exp": expires_at},
    )
    return str(gid)


def revoke(conn: Connection, *, actor: str, grant_id: str) -> Mapping[str, Any]:
    row = conn.execute(text("SELECT * FROM role_assignments WHERE id::text = :g"), {"g": grant_id}).mappings().first()
    if row is None:
        raise AdminError("no such grant", 404)
    if row["principal_type"] == "user" and str(row["principal_id"]) == str(actor):
        raise AdminError("segregation of duties: you cannot change your own roles", 403)
    if row["role"] == "platform_admin":
        raise AdminError("platform_admin is managed in the identity provider")
    conn.execute(text("DELETE FROM role_assignments WHERE id = :g"), {"g": row["id"]})
    return row


def users(conn: Connection, q: str = "") -> list[dict[str, Any]]:
    return [
        {"id": str(r.id), "display_name": r.display_name, "email": r.email, "logins": list(r.logins or [])}
        for r in conn.execute(
            text("""SELECT u.id, u.display_name, u.email,
                      array_remove(array_agg(DISTINCT i.login), NULL) AS logins
                    FROM users u LEFT JOIN user_identities i ON i.user_id = u.id
                    WHERE u.active AND (:q = '' OR u.display_name ILIKE :like OR u.email ILIKE :like
                                        OR i.login ILIKE :like)
                    GROUP BY u.id ORDER BY u.display_name LIMIT 100"""),
            {"q": q, "like": f"%{q}%"},
        )
    ]
