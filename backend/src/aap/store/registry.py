# SPDX-License-Identifier: Apache-2.0
"""Application registry persistence (E03): org units, people, applications, repositories, classification ledger."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from aap.domain.classification import ClassificationResult
from aap.ids import uuid7


def upsert_org_unit(conn: Connection, slug: str, name: str, unit_type: str, parent_id: str | None) -> str:
    """Create or rename a unit. The root (no parent) is the organization itself and exists once: asking for a root
    when one exists returns it unchanged."""
    if parent_id is None:
        root = conn.execute(text("SELECT id FROM org_units WHERE parent_id IS NULL")).first()
        if root is not None:
            return str(root.id)
    row = conn.execute(
        text("""INSERT INTO org_units (id, parent_id, unit_type, name, slug) VALUES (:id, :p, :t, :n, :s)
                ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id"""),
        {"id": uuid7(), "p": parent_id, "t": unit_type, "n": name, "s": slug},
    ).first()
    return str(row.id)


def upsert_user(
    conn: Connection,
    display_name: str,
    login: str | None = None,
    email: str | None = None,
    provider: str = "github",
    external_id: str | None = None,
) -> str:
    """A person, keyed by one identity: an SCM login (`provider` github/gitlab) or an IdP subject
    (`provider` 'oidc:<issuer>', `external_id` = subject). Re-running with the same identity updates the name."""
    if login is None and external_id is None:
        raise ValueError("a user needs a login or an external id")
    ext = str(external_id) if external_id is not None else f"login:{login}"
    row = conn.execute(
        text("""SELECT user_id FROM user_identities WHERE provider = :p
                AND (external_id = :x OR (CAST(:l AS text) IS NOT NULL AND lower(login) = lower(CAST(:l AS text)))) LIMIT 1"""),
        {"p": provider, "x": ext, "l": login},
    ).first()
    if row is not None:
        conn.execute(
            text("UPDATE users SET display_name = :n, email = COALESCE(:e, email) WHERE id = :id"),
            {"n": display_name, "e": email, "id": row.user_id},
        )
        return str(row.user_id)
    uid = uuid7()
    conn.execute(
        text("INSERT INTO users (id, display_name, email) VALUES (:id, :n, :e)"),
        {"id": uid, "n": display_name, "e": email},
    )
    add_identity(conn, str(uid), provider, ext, login)
    return str(uid)


def add_identity(conn: Connection, user_id: str, provider: str, external_id: str, login: str | None = None) -> None:
    conn.execute(
        text("""INSERT INTO user_identities (user_id, provider, external_id, login) VALUES (:u, :p, :x, :l)
                ON CONFLICT (provider, external_id) DO UPDATE SET login = COALESCE(EXCLUDED.login, user_identities.login)"""),
        {"u": user_id, "p": provider, "x": str(external_id), "l": login},
    )


def add_member(conn: Connection, org_unit_id: str, user_id: str) -> None:
    conn.execute(
        text("INSERT INTO org_unit_members (org_unit_id, user_id) VALUES (:o, :u) ON CONFLICT DO NOTHING"),
        {"o": org_unit_id, "u": user_id},
    )


def grant_role(conn: Connection, user_id: str, role: str, org_unit_id: str | None = None) -> None:
    exists = conn.execute(
        text(
            "SELECT 1 FROM role_assignments WHERE principal_type = 'user' AND principal_id = :u AND role = :r "
            "AND scope_org_unit_id IS NOT DISTINCT FROM CAST(:o AS uuid)"
        ),
        {"u": user_id, "r": role, "o": org_unit_id},
    ).first()
    if not exists:
        conn.execute(
            text(
                "INSERT INTO role_assignments (id, principal_type, principal_id, role, scope_org_unit_id) "
                "VALUES (:id, 'user', :u, :r, :o)"
            ),
            {"id": uuid7(), "u": user_id, "r": role, "o": org_unit_id},
        )


def upsert_repository(
    conn: Connection,
    external_id: int | str,
    full_name: str,
    visibility: str = "private",
    default_branch: str = "main",
    head_sha: str | None = None,
    detected: Mapping[str, Any] | None = None,
    provider: str = "github",
) -> str:
    row = conn.execute(
        text("""INSERT INTO repositories (id, provider, external_id, external_node_id, full_name, visibility, default_branch,
                  head_sha, detected, onboarding)
                VALUES (:id, :prov, :gid, :node, :name, :vis, :branch, :head, CAST(:det AS jsonb), 'onboarded')
                ON CONFLICT (provider, external_id) DO UPDATE SET full_name = EXCLUDED.full_name,
                  head_sha = COALESCE(EXCLUDED.head_sha, repositories.head_sha),
                  detected = COALESCE(EXCLUDED.detected, repositories.detected) RETURNING id"""),
        {
            "id": uuid7(),
            "prov": provider,
            "gid": str(external_id),
            "node": None,
            "name": full_name,
            "vis": visibility,
            "branch": default_branch,
            "head": head_sha,
            "det": json.dumps(dict(detected or {})),
        },
    ).first()
    return str(row.id)


@dataclass(frozen=True)
class NewApplication:
    name: str
    description: str
    org_unit_id: str
    lifecycle: str
    exposure: str
    data_classification: str
    personal_data: str
    profile: dict[str, Any]
    business_owner_id: str | None = None
    technical_owner_id: str | None = None
    champion_id: str | None = None


def create_application(conn: Connection, app: NewApplication) -> tuple[str, str]:
    row = conn.execute(
        text("""INSERT INTO applications (id, name, description, org_unit_id, business_owner_id, technical_owner_id,
                  champion_id, lifecycle, exposure, data_classification, personal_data, profile)
                VALUES (:id, :n, :d, :o, :bo, :to, :ch, :lc, :ex, :dc, :pd, CAST(:profile AS jsonb))
                RETURNING id, app_key"""),
        {
            "id": uuid7(),
            "n": app.name,
            "d": app.description,
            "o": app.org_unit_id,
            "bo": app.business_owner_id,
            "to": app.technical_owner_id,
            "ch": app.champion_id,
            "lc": app.lifecycle,
            "ex": app.exposure,
            "dc": app.data_classification,
            "pd": app.personal_data,
            "profile": json.dumps(app.profile),
        },
    ).first()
    return str(row.id), str(row.app_key)


def link_repository(conn: Connection, application_id: str, repository_id: str, role: str) -> None:
    conn.execute(
        text(
            "INSERT INTO application_repositories (application_id, repository_id, role) VALUES (:a, :r, :role) "
            "ON CONFLICT DO NOTHING"
        ),
        {"a": application_id, "r": repository_id, "role": role},
    )
    if role == "primary":  # the primary repository's .security/application.yaml is authoritative for the app
        conn.execute(
            text("UPDATE applications SET source_repo_id = :r WHERE id = :a AND source_repo_id IS NULL"),
            {"a": application_id, "r": repository_id},
        )


def record_classification(
    conn: Connection,
    application_id: str,
    model_version: str,
    inputs: Mapping[str, Any],
    result: ClassificationResult,
    decision: str,
    decided_by: str | None,
    requested_by: str | None = None,
    supersedes_id: str | None = None,
) -> str:
    row = conn.execute(
        text("""INSERT INTO application_classifications (id, application_id, model_version, inputs, matched_floor_rules,
                  points, computed_tier, decision, decided_by, decided_at, requested_by, supersedes_id)
                VALUES (:id, :a, :mv, CAST(:inputs AS jsonb), :rules, :pts, :tier, :dec, :by,
                        CASE WHEN :dec IN ('approved', 'auto_approved', 'rejected') THEN now() END, :req, :sup)
                RETURNING id"""),
        {
            "id": uuid7(),
            "a": application_id,
            "mv": model_version,
            "inputs": json.dumps(dict(inputs)),
            "rules": list(result.matched_floor_rules),
            "pts": result.points,
            "tier": result.tier,
            "dec": decision,
            "by": decided_by,
            "req": requested_by,
            "sup": supersedes_id,
        },
    ).first()
    if decision in ("approved", "auto_approved"):
        conn.execute(
            text("UPDATE applications SET tier_rank = :t, classification_id = :c WHERE id = :a"),
            {"t": result.tier, "c": row.id, "a": application_id},
        )
    return str(row.id)


def application_context(conn: Connection, application_id: str) -> Mapping[str, Any] | None:
    return (
        conn.execute(
            text("""SELECT a.*, o.slug AS org_slug, o.name AS org_name,
                  (SELECT json_agg(json_build_object('id', r.id, 'provider', r.provider, 'external_id', r.external_id, 'full_name', r.full_name,
                     'role', ar.role, 'head_sha', r.head_sha, 'detected', r.detected, 'visibility', r.visibility))
                   FROM application_repositories ar JOIN repositories r ON r.id = ar.repository_id
                   WHERE ar.application_id = a.id) AS repositories
                FROM applications a JOIN org_units o ON o.id = a.org_unit_id WHERE a.id = :a"""),
            {"a": application_id},
        )
        .mappings()
        .first()
    )


def application_by_repo(conn: Connection, external_id: int | str, provider: str = "github") -> Mapping[str, Any] | None:
    return (
        conn.execute(
            text("""SELECT a.id AS application_id, r.id AS repository_id, r.full_name, r.head_sha, r.default_branch
                FROM repositories r JOIN application_repositories ar ON ar.repository_id = r.id
                JOIN applications a ON a.id = ar.application_id
                WHERE r.provider = :p AND r.external_id = :g ORDER BY (ar.role = 'primary') DESC LIMIT 1"""),
            {"p": provider, "g": str(external_id)},
        )
        .mappings()
        .first()
    )
