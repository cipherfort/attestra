# SPDX-License-Identifier: Apache-2.0
"""Integrations: OIDC login state and server-side sessions (BFF, ADR-014), connector run history, SIEM dispatch.

None of these are ledgers. Sessions and login requests hold no tokens: only hashes of the opaque session id and
state, the PKCE verifier for the ≤ 10-minute login window, and the role/group claims the IdP asserted.

Revision ID: 0004_integrations
"""

from alembic import op

revision = "0004_integrations"
down_revision = "0003_api_grants"

SQL = """
SET search_path = aap, public;

CREATE TABLE web_auth_requests (
  state_hash      text PRIMARY KEY,               -- sha256(state); the state itself only travels in the redirect
  nonce           text NOT NULL,
  code_verifier   text NOT NULL,                  -- PKCE; single use, deleted on callback
  return_to       text NOT NULL DEFAULT '/',
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL
);

CREATE TABLE web_sessions (
  id_hash         text PRIMARY KEY,               -- sha256(session id); the id itself is only in the cookie
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_roles     text[] NOT NULL DEFAULT '{}',   -- app roles asserted by the IdP at sign-in
  token_groups    text[] NOT NULL DEFAULT '{}',   -- app-assigned group object ids (ApplicationGroup claim)
  csrf_token      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL            -- absolute lifetime; idle timeout checked against last_seen_at
);
CREATE INDEX web_sessions_user_idx ON web_sessions (user_id);

CREATE TABLE connector_runs (
  id              uuid PRIMARY KEY,
  connector       text NOT NULL,                  -- github-settings, dependency-track, jira, sentinel, ...
  target          text NOT NULL DEFAULT '',
  started_at      timestamptz NOT NULL DEFAULT now(),
  finished_at     timestamptz,
  status          text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'partial', 'failed')),
  items           integer NOT NULL DEFAULT 0,
  gaps            jsonb NOT NULL DEFAULT '{}'::jsonb,   -- what could not be read, and why (never silently "ok")
  error           text
);
CREATE INDEX connector_runs_recent_idx ON connector_runs (connector, started_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON web_auth_requests, web_sessions, connector_runs TO aap_worker;
GRANT SELECT ON connector_runs TO aap_api;
REVOKE ALL ON web_auth_requests, web_sessions FROM aap_api, aap_reporting;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
