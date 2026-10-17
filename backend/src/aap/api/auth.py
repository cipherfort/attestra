# SPDX-License-Identifier: Apache-2.0
"""Authentication (ADR-014).

`AAP_AUTH_MODE=oidc` (production; `entra` is an alias):
  * Browser: BFF. `/auth/login` → IdP (code + PKCE) → `/auth/callback` → server-side session, opaque `__Host-` cookie
    (HttpOnly, Secure, SameSite=Lax), 30-minute idle and 8-hour absolute timeout (ACM-08). Unsafe methods need the
    session's CSRF token in `X-AAP-CSRF`. No token ever reaches the browser.
  * Service clients: `Authorization: Bearer <access token>` for the platform API audience (client credentials).
`AAP_AUTH_MODE=dev`: `X-AAP-Dev-User: <github login>` for seeded users. Refused when `AAP_ENV=production`.

Roles: IdP app roles grant only `TOKEN_ROLES` (org-wide). Scoped roles come from `role_assignments` (by user, or by an
Entra group the token lists), and `engineer` from team membership. Settings: `oidc_settings()` below.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import Connection, Engine, text

from aap.api.oidc import OidcClient, OidcError, OidcSettings, managed_identity_assertion, pkce_pair
from aap.api.policy import SERVICE_ROLES, TOKEN_ROLES, Principal
from aap.db import Scope, transaction
from aap.ids import uuid7
from aap.store import registry

SESSION_COOKIE = "__Host-aap_session"
IDLE = timedelta(minutes=30)
ABSOLUTE = timedelta(hours=8)
LOGIN_WINDOW = timedelta(minutes=10)
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class AuthConfigurationError(RuntimeError):
    pass


def auth_mode() -> str:
    mode = os.environ.get("AAP_AUTH_MODE", "oidc")
    mode = "oidc" if mode == "entra" else mode
    if mode == "dev" and os.environ.get("AAP_ENV", "development") == "production":
        raise AuthConfigurationError("AAP_AUTH_MODE=dev is not permitted when AAP_ENV=production")
    if mode not in ("dev", "oidc"):
        raise AuthConfigurationError(f"unknown AAP_AUTH_MODE {mode!r}")
    return mode


def oidc_settings() -> OidcSettings:
    """AAP_OIDC_ISSUER (e.g. https://login.microsoftonline.com/<tenant>/v2.0), AAP_OIDC_CLIENT_ID, AAP_PUBLIC_URL,
    optional AAP_OIDC_API_AUDIENCE (bearer tokens) and AAP_OIDC_TENANT_ID (pin `tid`). Terraform outputs all of them."""
    missing = [v for v in ("AAP_OIDC_ISSUER", "AAP_OIDC_CLIENT_ID", "AAP_PUBLIC_URL") if not os.environ.get(v)]
    if missing:
        raise AuthConfigurationError(
            f"OIDC is not configured: set {', '.join(missing)} (see docs/install/helm.md and charts/attestra/README.md)"
        )
    public = os.environ["AAP_PUBLIC_URL"].rstrip("/")
    if os.environ.get("AAP_ENV") == "production" and not public.startswith("https://"):
        raise AuthConfigurationError("AAP_PUBLIC_URL must be https in production")
    return OidcSettings(
        issuer=os.environ["AAP_OIDC_ISSUER"],
        client_id=os.environ["AAP_OIDC_CLIENT_ID"],
        redirect_uri=f"{public}/auth/callback",
        api_audience=os.environ.get("AAP_OIDC_API_AUDIENCE"),
        tenant_id=os.environ.get("AAP_OIDC_TENANT_ID"),
        internal_url=os.environ.get("AAP_OIDC_INTERNAL_URL") or None,
        post_logout_redirect_uri=f"{public}/",
    )


def build_oidc_client() -> OidcClient:
    """Client authentication, strongest available first: managed-identity federated credential (no secret exists),
    else the `oidc-client-secret` secret (local mock IdP)."""
    from aap.secrets import require, secret_store

    settings = oidc_settings()
    mi = os.environ.get("AAP_AZURE_CLIENT_ID")
    if os.environ.get("AAP_OIDC_CLIENT_AUTH", "managed_identity" if mi else "secret") == "managed_identity":
        if not mi:
            raise AuthConfigurationError("AAP_OIDC_CLIENT_AUTH=managed_identity needs AAP_AZURE_CLIENT_ID")
        return OidcClient(settings, client_assertion=managed_identity_assertion(mi))
    if os.environ.get("AAP_ENV") == "production":
        raise AuthConfigurationError("client secrets are not permitted in production; use the managed identity")
    return OidcClient(
        settings, client_secret=require(secret_store(), "oidc-client-secret", "run aap bootstrap oidc-dev")
    )


def oidc_client(request: Request) -> OidcClient:
    client = getattr(request.app.state, "oidc", None)
    if client is None:
        try:
            client = build_oidc_client()
        except AuthConfigurationError as e:
            raise HTTPException(501, str(e)) from e
        request.app.state.oidc = client
    return client


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ------------------------------------------------------------------------------------------ principals


def _resolve(
    conn: Connection, user_id: Any, display: str, token_roles: tuple[str, ...], groups: tuple[str, ...]
) -> Principal:
    roles = conn.execute(
        text(
            """SELECT role, scope_org_unit_id FROM role_assignments
               WHERE ((principal_type = 'user' AND principal_id = :uid)
                   OR (principal_type = 'idp_group' AND principal_id = ANY(:groups)))
                 AND (expires_at IS NULL OR expires_at > now())"""
        ),
        {"uid": str(user_id), "groups": list(groups)},
    ).all()
    units = conn.execute(
        text("""WITH RECURSIVE base AS (
                  SELECT org_unit_id AS id FROM org_unit_members WHERE user_id = :u
                  UNION SELECT scope_org_unit_id FROM role_assignments
                    WHERE ((principal_type = 'user' AND principal_id = :uid)
                        OR (principal_type = 'idp_group' AND principal_id = ANY(:groups)))
                      AND scope_org_unit_id IS NOT NULL AND (expires_at IS NULL OR expires_at > now())),
                tree AS (SELECT id FROM base UNION SELECT o.id FROM org_units o JOIN tree t ON o.parent_id = t.id)
                SELECT id FROM tree"""),
        {"u": user_id, "uid": str(user_id), "groups": list(groups)},
    ).all()
    is_member = (
        conn.execute(text("SELECT 1 FROM org_unit_members WHERE user_id = :u LIMIT 1"), {"u": user_id}).first()
        is not None
    )
    # `engineer` comes only from team membership (or an explicit app role), never by default: an org-wide role such as
    # executive must not inherit finding-level read access (access control model section 3).
    names = {r.role for r in roles} | (set(token_roles) & TOKEN_ROLES) | ({"engineer"} if is_member else set())
    return Principal(str(user_id), display, tuple(sorted(names)), tuple(str(u.id) for u in units))


def resolve_principal(engine: Engine, login: str) -> Principal | None:
    """Development identities: a seeded user by source-control login."""
    with transaction(engine, "aap_auth") as conn:  # identity lookup: the narrow sign-in role, not user-scoped
        user = conn.execute(
            text("""SELECT u.id, u.display_name FROM users u JOIN user_identities i ON i.user_id = u.id
                    WHERE i.provider NOT LIKE 'oidc:%' AND lower(i.login) = lower(:l) AND u.active LIMIT 1"""),
            {"l": login},
        ).first()
        if user is None:
            return None
        return _resolve(conn, user.id, user.display_name, (), ())


def upsert_oidc_user(conn: Connection, claims: dict[str, Any], link_by_email: bool) -> tuple[Any, str]:
    """Just-in-time user record keyed by the issuer and the immutable subject (`oid` when the IdP has one, as Entra
    does; else `sub`). A pre-registered user (from the registry, e.g. an owner named in application.yaml) is linked by
    email only for a single pinned tenant, whose addresses the organisation controls; never across tenants."""
    provider = f"oidc:{claims['iss']}"
    subject = str(claims.get("oid") or claims["sub"])
    name = str(claims.get("name") or claims.get("preferred_username") or "unknown")
    email = str(claims.get("email") or claims.get("preferred_username") or "") or None
    row = conn.execute(
        text("""SELECT u.id, u.active FROM users u JOIN user_identities i ON i.user_id = u.id
                WHERE i.provider = :p AND i.external_id = :x"""),
        {"p": provider, "x": subject},
    ).first()
    if row is None and link_by_email and email:
        row = conn.execute(
            text("""SELECT u.id, u.active FROM users u WHERE lower(u.email) = lower(:e)
                    AND NOT EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = u.id AND i.provider = :p)"""),
            {"e": email, "p": provider},
        ).first()
    if row is not None:
        if not row.active:
            raise OidcError("user is deactivated")
        conn.execute(
            text(
                "UPDATE users SET display_name = :n, email = COALESCE(:e, email), last_synced_at = now() WHERE id = :id"
            ),
            {"n": name, "e": email, "id": row.id},
        )
        registry.add_identity(conn, str(row.id), provider, subject, claims.get("preferred_username"))
        return row.id, name
    uid = uuid7()
    conn.execute(
        text("INSERT INTO users (id, display_name, email, last_synced_at) VALUES (:id, :n, :e, now())"),
        {"id": uid, "n": name, "e": email},
    )
    registry.add_identity(conn, str(uid), provider, subject, claims.get("preferred_username"))
    return uid, name


# ------------------------------------------------------------------------------------------ sessions


@dataclass(frozen=True)
class NewSession:
    cookie_value: str
    csrf_token: str


def start_login(engine: Engine, return_to: str) -> tuple[str, str, str]:
    """Returns (state, nonce, code_verifier); stores the state hash, nonce and verifier for ≤ 10 minutes."""
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, _ = pkce_pair()
    with transaction(engine, "aap_auth") as conn:
        conn.execute(text("DELETE FROM web_auth_requests WHERE expires_at < now()"))
        conn.execute(
            text("""INSERT INTO web_auth_requests (state_hash, nonce, code_verifier, return_to, expires_at)
                    VALUES (:s, :n, :v, :r, now() + make_interval(secs => :ttl))"""),
            {"s": _h(state), "n": nonce, "v": verifier, "r": safe_return_to(return_to), "ttl": LOGIN_WINDOW.seconds},
        )
    return state, nonce, verifier


def take_login(engine: Engine, state: str) -> tuple[str, str, str]:
    """Single use: the row is deleted whether or not the rest of the callback succeeds."""
    with transaction(engine, "aap_auth") as conn:
        row = conn.execute(
            text("""DELETE FROM web_auth_requests WHERE state_hash = :s AND expires_at > now()
                    RETURNING nonce, code_verifier, return_to"""),
            {"s": _h(state)},
        ).first()
    if row is None:
        raise OidcError("unknown or expired login state")
    return row.nonce, row.code_verifier, row.return_to


def create_session(engine: Engine, claims: dict[str, Any], link_by_email: bool) -> NewSession:
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with transaction(engine, "aap_auth") as conn:
        user_id, _ = upsert_oidc_user(conn, claims, link_by_email)
        conn.execute(
            text("""INSERT INTO web_sessions (id_hash, user_id, token_roles, token_groups, csrf_token, expires_at)
                    VALUES (:h, :u, :r, :g, :c, now() + make_interval(secs => :ttl))"""),
            {
                "h": _h(sid),
                "u": user_id,
                "r": [str(r) for r in claims.get("roles") or []],
                "g": [str(g) for g in claims.get("groups") or []],
                "c": csrf,
                "ttl": int(ABSOLUTE.total_seconds()),
            },
        )
    return NewSession(sid, csrf)


def end_session(engine: Engine, cookie_value: str) -> None:
    with transaction(engine, "aap_auth") as conn:
        conn.execute(text("DELETE FROM web_sessions WHERE id_hash = :h"), {"h": _h(cookie_value)})


def session_principal(engine: Engine, cookie_value: str, method: str, csrf_header: str | None) -> Principal:
    with transaction(engine, "aap_auth") as conn:
        row = conn.execute(
            text("""UPDATE web_sessions s SET last_seen_at = now()
                    FROM users u
                    WHERE s.id_hash = :h AND u.id = s.user_id AND u.active
                      AND s.expires_at > now() AND s.last_seen_at > now() - make_interval(secs => :idle)
                    RETURNING s.user_id, u.display_name, s.token_roles, s.token_groups, s.csrf_token"""),
            {"h": _h(cookie_value), "idle": int(IDLE.total_seconds())},
        ).first()
        if row is None:
            conn.execute(text("DELETE FROM web_sessions WHERE id_hash = :h"), {"h": _h(cookie_value)})
            raise HTTPException(401, "session expired")
        if method in UNSAFE and not (csrf_header and secrets.compare_digest(csrf_header, row.csrf_token)):
            raise HTTPException(403, "missing or invalid X-AAP-CSRF header")
        p = _resolve(conn, row.user_id, row.display_name, tuple(row.token_roles), tuple(row.token_groups))
    return Principal(p.user_id, p.display_name, p.roles, p.org_units, extra={"csrf": row.csrf_token})


def bearer_principal(request: Request, token: str) -> Principal:
    try:
        claims = oidc_client(request).validate_access_token(token)
    except OidcError as e:
        raise HTTPException(401, str(e)) from e
    if "scp" in claims:  # delegated user tokens go through the BFF, not bearer
        raise HTTPException(401, "delegated tokens are not accepted; use the web sign-in")
    roles = tuple(sorted({SERVICE_ROLES[r] for r in claims.get("roles") or [] if r in SERVICE_ROLES}))
    who = str(claims.get("azp") or claims.get("appid") or claims["sub"])
    return Principal(f"service:{claims.get('oid') or claims['sub']}", f"service {who}", roles, (), kind="service")


def safe_return_to(value: str | None) -> str:
    """Only same-origin absolute paths: no scheme, no `//host`, no backslash tricks."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return "/"
    return value


# ------------------------------------------------------------------------------------------ request entry point


def authenticate(request: Request) -> Principal:
    mode = auth_mode()
    engine = request.app.state.engine
    if mode == "dev":
        login = request.headers.get("X-AAP-Dev-User")
        if not login:
            raise HTTPException(401, "missing X-AAP-Dev-User (dev auth mode)")
        principal = resolve_principal(engine, login)
        if principal is None:
            raise HTTPException(401, "unknown user")
        return principal
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return bearer_principal(request, auth[7:].strip())
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return session_principal(engine, cookie, request.method, request.headers.get("X-AAP-CSRF"))
    raise HTTPException(401, "sign in required")


def scope_for(p: Principal) -> Scope:
    return Scope(scope_all=p.org_wide, org_units=p.org_units)
