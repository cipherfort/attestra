# SPDX-License-Identifier: Apache-2.0
"""Database access.

Every unit of work runs inside `transaction(role, scope)`, which issues `SET LOCAL ROLE` to one of the platform's
NOLOGIN roles and sets the row-level-security scope for that transaction only. Application code never runs
queries with the connecting login's own privileges, so a superuser login (local dev) still gets RLS and ledger
guards exactly as production does.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache

from sqlalchemy import Connection, Engine, create_engine, text

ROLES = frozenset({"aap_api", "aap_auth", "aap_admin", "aap_worker", "aap_hook", "aap_reporting"})


@dataclass(frozen=True)
class Scope:
    """Row-level-security scope for an API request (ADR-013/022). Workers run unscoped as aap_worker."""

    scope_all: bool = False
    org_units: tuple[str, ...] = field(default_factory=tuple)


def database_url() -> str:
    """AAP_DATABASE_URL, or the contents of AAP_DATABASE_URL_FILE (a mounted secret; keeps the password out of the
    environment and out of aap.yaml)."""
    url = os.environ.get("AAP_DATABASE_URL")
    if not url and os.environ.get("AAP_DATABASE_URL_FILE"):
        url = open(os.environ["AAP_DATABASE_URL_FILE"]).read().strip()  # noqa: SIM115 - read once at startup
    if not url:
        raise RuntimeError("AAP_DATABASE_URL (or AAP_DATABASE_URL_FILE) is not set")
    return url


@lru_cache(maxsize=4)
def get_engine(url: str | None = None) -> Engine:
    return create_engine(url or database_url(), pool_pre_ping=True, pool_size=5, max_overflow=5)


@contextmanager
def transaction(engine: Engine, role: str, scope: Scope | None = None) -> Iterator[Connection]:
    if role not in ROLES:
        raise ValueError(f"unknown database role {role!r}")
    with engine.begin() as conn:
        conn.exec_driver_sql(f"SET LOCAL ROLE {role}")  # role from a fixed allowlist, never user input
        conn.exec_driver_sql("SET LOCAL search_path = aap, public")
        if scope is not None:
            conn.execute(
                text("SELECT set_config('aap.scope_all', :all, true), set_config('aap.org_units', :units, true)"),
                {"all": "on" if scope.scope_all else "off", "units": "{" + ",".join(scope.org_units) + "}"},
            )
        yield conn


@contextmanager
def admin_connection(engine: Engine) -> Iterator[Connection]:
    """Migrator/maintenance only (migrations, partition maintenance). Never used by request or job handling."""
    with engine.begin() as conn:
        conn.exec_driver_sql("SET LOCAL search_path = aap, public")
        yield conn


PROCESS_LOGINS = {
    "aap_api_login": ("aap_api", "aap_auth", "aap_admin"),
    "aap_worker_login": ("aap_worker",),
    "aap_hook_login": ("aap_hook",),
    "aap_reporting_login": ("aap_reporting",),
}


def set_login_password(engine: Engine, login: str, password: str) -> None:
    """Administrator only (migration identity). The password is quoted by the server (format %L), never interpolated
    in Python, and never logged."""
    if login not in PROCESS_LOGINS:
        raise ValueError(f"unknown login {login!r}")
    with engine.begin() as conn:
        stmt = conn.execute(
            text("SELECT format('ALTER ROLE %I PASSWORD %L', CAST(:l AS text), CAST(:p AS text))"),
            {"l": login, "p": password},
        ).scalar_one()
        conn.exec_driver_sql(stmt)
