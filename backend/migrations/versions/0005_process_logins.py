# SPDX-License-Identifier: Apache-2.0
"""Per-process database logins and a narrow role for sign-in (risk R-25).

Before: every process connected as the administrator and switched to a role per transaction, so a compromised API
process could switch to `aap_worker` (unscoped reads, evidence writes). Now:

* `aap_auth` (NOLOGIN): only what sign-in needs: users, identities, memberships, role assignments, sessions.
* One LOGIN role per process, NOINHERIT (no privileges until it switches role), member only of the roles it uses:
    aap_api_login       → aap_api, aap_auth
    aap_worker_login    → aap_worker
    aap_hook_login      → aap_hook
    aap_reporting_login → aap_reporting
  The administrator login is used only by migrations. Logins are created without a password; set one with
  `aap db set-password <login>` (or use the database's own identity integration, e.g. Entra auth in Azure).

Revision ID: 0005_process_logins
"""

from alembic import op

revision = "0005_process_logins"
down_revision = "0004_integrations"

SQL = """
SET search_path = aap, public;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_auth') THEN CREATE ROLE aap_auth NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA aap TO aap_auth;
GRANT SELECT ON users, user_identities, org_units, org_unit_members, role_assignments TO aap_auth;
GRANT INSERT, UPDATE ON users, user_identities TO aap_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON web_sessions, web_auth_requests TO aap_auth;

DO $$
DECLARE
  login text;
  memberships text[];
  pairs text[][] := ARRAY[
    ARRAY['aap_api_login', 'aap_api,aap_auth'],
    ARRAY['aap_worker_login', 'aap_worker'],
    ARRAY['aap_hook_login', 'aap_hook'],
    ARRAY['aap_reporting_login', 'aap_reporting']];
  i int;
  r text;
BEGIN
  FOR i IN 1 .. array_length(pairs, 1) LOOP
    login := pairs[i][1];
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = login) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOINHERIT', login);
    END IF;
    FOREACH r IN ARRAY string_to_array(pairs[i][2], ',') LOOP
      EXECUTE format('GRANT %I TO %I', r, login);
    END LOOP;
  END LOOP;
END $$;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
