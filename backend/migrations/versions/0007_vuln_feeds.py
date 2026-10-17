# SPDX-License-Identifier: Apache-2.0
"""Built-in vulnerability feeds (M2): findings raised from OSV matches carry source_system 'osv'.

Revision ID: 0007_vuln_feeds
"""

from alembic import op

revision = "0007_vuln_feeds"
down_revision = "0006_onboarding"

SQL = """
SET search_path = aap, public;
ALTER TYPE source_system ADD VALUE IF NOT EXISTS 'osv';
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
