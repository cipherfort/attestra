# SPDX-License-Identifier: Apache-2.0
"""Administration (M2): a narrow `aap_admin` role for the admin screens (org units, memberships, scoped role grants).

Kept apart from `aap_api` so ordinary request handling can never change who sees what: only the admin endpoints
(permission org.admin) switch to this role, and every change they make is audited. Unit *moves* (parent_id) are
not granted: re-parenting changes row-level security scope for every application below, so it stays a migration.

Revision ID: 0009_admin_role
"""

from alembic import op

revision = "0009_admin_role"
down_revision = "0008_assessments_rls"

SQL = """
SET search_path = aap, public;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_admin') THEN CREATE ROLE aap_admin NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA aap TO aap_admin;
GRANT SELECT ON org_units, org_unit_members, role_assignments, users, user_identities, applications TO aap_admin;
GRANT INSERT ON org_units TO aap_admin;
GRANT UPDATE (name, scm_group, idp_group_id) ON org_units TO aap_admin;
GRANT INSERT, DELETE ON org_unit_members, role_assignments TO aap_admin;
GRANT SELECT, INSERT ON audit_events TO aap_admin;   -- the hash chain reads the previous record
GRANT USAGE ON ALL SEQUENCES IN SCHEMA aap TO aap_admin;
-- the unit tree shows how many applications each unit owns (counts only; admins have no application.read)
DROP POLICY IF EXISTS applications_admin ON applications;
CREATE POLICY applications_admin ON applications FOR SELECT TO aap_admin USING (true);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_api_login') THEN GRANT aap_admin TO aap_api_login; END IF;
END $$;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
