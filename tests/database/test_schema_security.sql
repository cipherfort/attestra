-- SPDX-License-Identifier: Apache-2.0
-- Security-property tests for schemas/database/0001_core.sql
-- Run: tests/database/run.sh   (applies the schema to a throwaway postgres:16 container, then this file)
-- Each block raises on failure; ON_ERROR_STOP makes psql exit non-zero.
\set ON_ERROR_STOP on
SET search_path = aap, public;

-- ---------------------------------------------------------------- fixtures
INSERT INTO org_units (id, unit_type, name, slug) VALUES ('00000000-0000-0000-0000-000000000001', 'organisation', 'Org', 'org');
INSERT INTO org_units (id, parent_id, unit_type, name, slug) VALUES
  ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-000000000001', 'team', 'Team A', 'team-a'),
  ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-000000000001', 'team', 'Team B', 'team-b');
INSERT INTO users (id, display_name) VALUES
  ('00000000-0000-0000-0000-0000000000a1', 'Alice'),
  ('00000000-0000-0000-0000-0000000000b1', 'Bob');
INSERT INTO user_identities (user_id, provider, external_id, login) VALUES
  ('00000000-0000-0000-0000-0000000000a1', 'oidc:https://idp.example.org', 'sub-alice', 'alice@example.org'),
  ('00000000-0000-0000-0000-0000000000a1', 'github', '1001', 'alice');
INSERT INTO applications (id, name, org_unit_id) VALUES
  ('00000000-0000-0000-0000-0000000000aa', 'App A', '00000000-0000-0000-0000-00000000000a'),
  ('00000000-0000-0000-0000-0000000000bb', 'App B', '00000000-0000-0000-0000-00000000000b');
INSERT INTO findings (fingerprint, application_id, scope_type, scope_ref, finding_type, source_system, title, first_seen_at, last_seen_at)
VALUES ('fp-a', '00000000-0000-0000-0000-0000000000aa', 'repository', 'r1', 'code', 'ghas', 'Finding in A', now(), now()),
       ('fp-b', '00000000-0000-0000-0000-0000000000bb', 'repository', 'r2', 'code', 'ghas', 'Finding in B', now(), now());
INSERT INTO evidence (evidence_id, evidence_type, application_id, scope_type, scope_ref, subject, producer_type, producer_ref,
                      observed_at, result, confidence, record_hash)
VALUES (gen_random_uuid(), 'scan.sast', '00000000-0000-0000-0000-0000000000aa', 'repository', 'r1',
        '{"commit_sha":"3f2a9c0000000000000000000000000000000000"}', 'approved_workflow', 'wf@sha', now(), 'pass', 'C3', '\x00');

-- ---------------------------------------------------------------- T1: evidence ledger is immutable (even for the owner)
DO $$ BEGIN
  BEGIN
    UPDATE evidence SET result = 'fail';
    RAISE EXCEPTION 'T1 FAILED: UPDATE on evidence succeeded';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T1a ok: UPDATE blocked';
  END;
  BEGIN
    DELETE FROM evidence;
    RAISE EXCEPTION 'T1 FAILED: DELETE on evidence succeeded';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T1b ok: DELETE blocked';
  END;
  BEGIN
    TRUNCATE evidence;
    RAISE EXCEPTION 'T1 FAILED: TRUNCATE on evidence succeeded';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T1c ok: TRUNCATE blocked';
  END;
END $$;

-- ---------------------------------------------------------------- T2: SoD on exceptions (requester cannot approve)
DO $$ BEGIN
  BEGIN
    INSERT INTO exceptions (application_id, target_type, target_ref, justification, risk_description, residual_priority,
                            remediation_plan, owner_id, requested_by, approver_id, status, approved_at, starts_at, expires_at)
    VALUES ('00000000-0000-0000-0000-0000000000aa', 'control', 'ASC-BLD-01', 'j', 'r', 'P3', 'plan',
            '00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a1',
            '00000000-0000-0000-0000-0000000000a1', 'approved', now(), now(), now() + interval '30 days');
    RAISE EXCEPTION 'T2 FAILED: self-approved exception accepted';
  EXCEPTION WHEN check_violation THEN RAISE NOTICE 'T2 ok: self-approval rejected';
  END;
END $$;

-- ---------------------------------------------------------------- T3: approved exception must have expiry
DO $$ BEGIN
  BEGIN
    INSERT INTO exceptions (application_id, target_type, target_ref, justification, risk_description, residual_priority,
                            remediation_plan, owner_id, requested_by, approver_id, status, approved_at)
    VALUES ('00000000-0000-0000-0000-0000000000aa', 'control', 'ASC-BLD-01', 'j', 'r', 'P3', 'plan',
            '00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a1',
            '00000000-0000-0000-0000-0000000000b1', 'approved', now());
    RAISE EXCEPTION 'T3 FAILED: approved exception without expiry accepted';
  EXCEPTION WHEN check_violation THEN RAISE NOTICE 'T3 ok: open-ended exception rejected';
  END;
END $$;

-- ---------------------------------------------------------------- T4: finding cannot be closed without verification evidence
DO $$ BEGIN
  BEGIN
    UPDATE findings SET status = 'closed', closed_at = now() WHERE fingerprint = 'fp-a';
    RAISE EXCEPTION 'T4 FAILED: finding closed without closure evidence';
  EXCEPTION WHEN check_violation THEN RAISE NOTICE 'T4 ok: closure requires evidence';
  END;
END $$;

-- ---------------------------------------------------------------- T5: RLS: team A caller sees only team A data
SET ROLE aap_api;
DO $$ BEGIN PERFORM set_config('aap.scope_all', 'off', false); END $$;
DO $$ BEGIN PERFORM set_config('aap.org_units', '{00000000-0000-0000-0000-00000000000a}', false); END $$;
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM aap.findings;
  IF n <> 1 THEN RAISE EXCEPTION 'T5 FAILED: expected 1 visible finding, got %', n; END IF;
  SELECT count(*) INTO n FROM aap.findings WHERE application_id = '00000000-0000-0000-0000-0000000000bb';
  IF n <> 0 THEN RAISE EXCEPTION 'T5 FAILED: team B finding visible to team A'; END IF;
  SELECT count(*) INTO n FROM aap.applications;
  IF n <> 1 THEN RAISE EXCEPTION 'T5 FAILED: expected 1 visible application, got %', n; END IF;
  RAISE NOTICE 'T5 ok: RLS scopes findings and applications';
END $$;

-- ---------------------------------------------------------------- T6: RLS: no settings → sees nothing (fail closed)
DO $$ BEGIN PERFORM set_config('aap.org_units', '', false); END $$;
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM aap.findings;
  IF n <> 0 THEN RAISE EXCEPTION 'T6 FAILED: unscoped session saw % findings', n; END IF;
  RAISE NOTICE 'T6 ok: unscoped session fails closed';
END $$;

-- ---------------------------------------------------------------- T7: api role cannot write findings into another team's app
DO $$ BEGIN PERFORM set_config('aap.org_units', '{00000000-0000-0000-0000-00000000000a}', false); END $$;
DO $$ BEGIN
  BEGIN
    INSERT INTO aap.risks (application_id, source, title, status) VALUES ('00000000-0000-0000-0000-0000000000bb', 'manual', 'x', 'open');
    RAISE EXCEPTION 'T7 FAILED: cross-team insert succeeded';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T7 ok: cross-team write blocked by RLS';
  END;
END $$;

-- ---------------------------------------------------------------- T8: api role cannot read partitions directly (RLS bypass path)
DO $$
DECLARE part text;
BEGIN
  SELECT c.relname INTO part FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
   JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'evidence' LIMIT 1;
  BEGIN
    EXECUTE format('SELECT count(*) FROM aap.%I', part);
    RAISE EXCEPTION 'T8 FAILED: direct partition read allowed on %', part;
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T8 ok: direct partition access denied (%)', part;
  END;
END $$;

-- ---------------------------------------------------------------- T9: api role cannot insert evidence (only workers ingest)
DO $$ BEGIN
  BEGIN
    INSERT INTO aap.evidence (evidence_id, evidence_type, application_id, scope_type, scope_ref, subject, producer_type,
                              producer_ref, observed_at, result, confidence, record_hash)
    VALUES (gen_random_uuid(), 'scan.sast', '00000000-0000-0000-0000-0000000000aa', 'repository', 'r1', '{}',
            'manual', 'me', now(), 'pass', 'C3', '\x00');
    RAISE EXCEPTION 'T9 FAILED: api role inserted evidence';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T9 ok: api cannot forge evidence';
  END;
END $$;
RESET ROLE;

-- ---------------------------------------------------------------- T10: worker cannot UPDATE ledger (grant-level, not just trigger)
SET ROLE aap_worker;
DO $$ BEGIN
  BEGIN
    UPDATE aap.control_evaluations SET state = 'satisfied';
    RAISE EXCEPTION 'T10 FAILED: worker updated control_evaluations';
  EXCEPTION WHEN insufficient_privilege THEN RAISE NOTICE 'T10 ok: worker has no UPDATE on ledger';
  END;
END $$;
RESET ROLE;

-- ---------------------------------------------------------------- T11: exactly one root organization; identities unique per provider
DO $$ BEGIN
  BEGIN
    INSERT INTO org_units (unit_type, name, slug) VALUES ('organisation', 'Second root', 'second-root');
    RAISE EXCEPTION 'T11 FAILED: a second root org unit was accepted';
  EXCEPTION WHEN unique_violation THEN RAISE NOTICE 'T11a ok: single root enforced';
  END;
  BEGIN
    INSERT INTO user_identities (user_id, provider, external_id, login)
    VALUES ('00000000-0000-0000-0000-0000000000b1', 'github', '2002', 'ALICE');
    RAISE EXCEPTION 'T11 FAILED: a duplicate SCM login (case-insensitive) was accepted';
  EXCEPTION WHEN unique_violation THEN RAISE NOTICE 'T11b ok: SCM logins unique per provider, case-insensitively';
  END;
END $$;

\echo 'ALL SCHEMA SECURITY TESTS PASSED'
