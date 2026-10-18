# SPDX-License-Identifier: Apache-2.0
"""Monthly posture snapshots (component C13): trend metrics beside the existing SAMM maturity snapshots.

`maturity_snapshots` (one row per month) and `maturity_scores` (SAMM scores per application and org unit) existed
but nothing wrote them. The snapshot job now does, and `posture_metrics` adds the numbers the trend charts need:
mandatory controls proven, open findings by priority, evidence accepted and rejected.

The current month's snapshot is provisional (recomputed daily, `published = false`); it is published, and from then
on never changed, once the month is over. Row-level security: application rows are visible only where the
application is (same rule as findings and control states); organisation rows are aggregates.

Revision ID: 0010_posture_snapshots
"""

from alembic import op

revision = "0010_posture_snapshots"
down_revision = "0009_admin_role"

SQL = """
SET search_path = aap, public;
CREATE TABLE IF NOT EXISTS posture_metrics (
  snapshot_id   uuid NOT NULL REFERENCES maturity_snapshots(id),
  scope_type    text NOT NULL CHECK (scope_type IN ('application', 'organisation')),
  scope_id      uuid NOT NULL,              -- application id or org unit id
  metric        text NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_]{1,62}$'),
  value         numeric NOT NULL,
  PRIMARY KEY (snapshot_id, scope_type, scope_id, metric)
);
GRANT SELECT ON posture_metrics TO aap_api, aap_reporting;
GRANT SELECT, INSERT, DELETE ON posture_metrics TO aap_worker;
GRANT SELECT, INSERT, UPDATE ON maturity_snapshots TO aap_worker;
GRANT SELECT, INSERT, DELETE ON maturity_scores TO aap_worker;

-- a published snapshot is history: no change, no deletion
CREATE OR REPLACE FUNCTION snapshot_guard() RETURNS trigger LANGUAGE plpgsql AS $fn$
DECLARE published boolean;
BEGIN
  IF TG_TABLE_NAME = 'maturity_snapshots' THEN
    IF OLD.published THEN RAISE EXCEPTION 'snapshot % is published and immutable', OLD.period; END IF;
    RETURN NEW;
  END IF;
  SELECT s.published INTO published FROM maturity_snapshots s WHERE s.id = OLD.snapshot_id;
  IF published THEN RAISE EXCEPTION 'snapshot rows of a published snapshot are immutable'; END IF;
  RETURN OLD;
END $fn$;
DROP TRIGGER IF EXISTS maturity_snapshots_guard ON maturity_snapshots;
CREATE TRIGGER maturity_snapshots_guard BEFORE UPDATE ON maturity_snapshots FOR EACH ROW EXECUTE FUNCTION snapshot_guard();
DROP TRIGGER IF EXISTS maturity_scores_guard ON maturity_scores;
CREATE TRIGGER maturity_scores_guard BEFORE UPDATE OR DELETE ON maturity_scores FOR EACH ROW EXECUTE FUNCTION snapshot_guard();
DROP TRIGGER IF EXISTS posture_metrics_guard ON posture_metrics;
CREATE TRIGGER posture_metrics_guard BEFORE UPDATE OR DELETE ON posture_metrics FOR EACH ROW EXECUTE FUNCTION snapshot_guard();

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['maturity_scores', 'posture_metrics'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_scope', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT TO aap_api USING (scope_type = ''organisation'' OR app_visible(scope_id))', t || '_scope', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_worker', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR ALL TO aap_worker USING (true) WITH CHECK (true)', t || '_worker', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_reporting', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT TO aap_reporting USING (true)', t || '_reporting', t);
  END LOOP;
END $$;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)
