# SPDX-License-Identifier: Apache-2.0
"""API and receiver write paths: finding triage (status columns only, still RLS-scoped); hook enqueue.

Revision ID: 0003_api_grants
"""

from alembic import op

revision = "0003_api_grants"
down_revision = "0002_runtime"

SQL = """
SET search_path = aap, public;
GRANT UPDATE (status, closed_at, updated_at) ON findings TO aap_api;
-- the receiver's enqueue uses INSERT ... ON CONFLICT (queue, dedup_key) WHERE ... RETURNING id: PostgreSQL needs
-- SELECT on the arbiter/predicate columns. Payloads stay unreadable to the receiver.
GRANT SELECT (id, queue, dedup_key, status) ON jobs TO aap_hook;
"""


def _execute_script(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    _execute_script(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
