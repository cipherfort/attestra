# SPDX-License-Identifier: Apache-2.0
"""Runtime additions for the backend: webhook receiver role, repository head tracking, partition maintenance.

Revision ID: 0002_runtime
"""

from alembic import op

revision = "0002_runtime"
down_revision = "0001_core"

SQL = r"""
SET search_path = aap, public;

-- The internet-facing webhook receiver may only record deliveries and enqueue jobs (threat T-04, ADR-025).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_hook') THEN CREATE ROLE aap_hook NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA aap TO aap_hook;
GRANT INSERT ON webhook_deliveries, jobs TO aap_hook;
GRANT SELECT (delivery_id) ON webhook_deliveries TO aap_hook;
GRANT USAGE ON SEQUENCE jobs_id_seq TO aap_hook;

-- Identity sync (Entra groups → roles) is a worker job.
GRANT INSERT, UPDATE, DELETE ON role_assignments TO aap_worker;

-- Default-branch head per repository: the freshness engine compares evidence commits against it.
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS head_sha text CHECK (head_sha IS NULL OR head_sha ~ '^[0-9a-f]{40}$');
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS detected jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Partition maintenance (run by the migrator / scheduled maintenance job, never by application roles).
CREATE OR REPLACE FUNCTION ensure_partitions(months_ahead int DEFAULT 2) RETURNS int LANGUAGE plpgsql AS $fn$
DECLARE
  m date := date_trunc('month', now())::date;
  t text; part text; created int := 0;
BEGIN
  FOREACH t IN ARRAY ARRAY['evidence', 'control_evaluations', 'finding_events', 'audit_events'] LOOP
    FOR i IN 0..months_ahead LOOP
      part := t || '_' || to_char(m + (i || ' month')::interval, 'YYYY_MM');
      IF to_regclass('aap.' || part) IS NULL THEN
        EXECUTE format('CREATE TABLE aap.%I PARTITION OF aap.%I FOR VALUES FROM (%L) TO (%L)', part, t,
                       m + (i || ' month')::interval, m + ((i + 1) || ' month')::interval);
        -- partitions do not inherit RLS: no direct access for application roles (schema test T8)
        EXECUTE format('REVOKE ALL ON aap.%I FROM aap_api, aap_worker, aap_reporting, aap_hook', part);
        created := created + 1;
      END IF;
    END LOOP;
  END LOOP;
  RETURN created;
END $fn$;
REVOKE ALL ON FUNCTION ensure_partitions(int) FROM PUBLIC;
"""


def _execute_script(sql: str) -> None:
    # Raw driver call without parameters: psycopg then sends the script verbatim (no %-placeholder parsing).
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    _execute_script(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
