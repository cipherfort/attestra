# SPDX-License-Identifier: Apache-2.0
"""Assessments API (M2): row-level security on assessments, like every other application-scoped table, so the API
role can only see and change assessments of applications in the caller's scope (defence in depth).

Revision ID: 0008_assessments_rls
"""

from alembic import op

revision = "0008_assessments_rls"
down_revision = "0007_vuln_feeds"

SQL = """
SET search_path = aap, public;
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS assessments_scope ON assessments;
CREATE POLICY assessments_scope ON assessments FOR ALL TO aap_api
  USING (application_id IS NOT NULL AND app_visible(application_id))
  WITH CHECK (application_id IS NOT NULL AND app_visible(application_id));
DROP POLICY IF EXISTS assessments_worker ON assessments;
CREATE POLICY assessments_worker ON assessments FOR ALL TO aap_worker USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS assessments_reporting ON assessments;
CREATE POLICY assessments_reporting ON assessments FOR SELECT TO aap_reporting USING (true);
GRANT INSERT ON jobs TO aap_api;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
