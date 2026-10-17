# SPDX-License-Identifier: Apache-2.0
"""Core schema: applies schemas/database/0001_core.sql (verified by tests/database/run.sh).

Revision ID: 0001_core
"""

from alembic import op

from aap.config import repo_root

revision = "0001_core"
down_revision = None


def _execute_script(sql: str) -> None:
    # Raw driver call without parameters: psycopg then sends the script verbatim (no %-placeholder parsing).
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    sql = (repo_root() / "schemas/database/0001_core.sql").read_text()
    _execute_script(sql)


def downgrade() -> None:
    raise RuntimeError("the core schema holds immutable ledgers and is never downgraded")
