-- SPDX-License-Identifier: Apache-2.0
-- =============================================================================
-- Attestra: core schema (PostgreSQL 16)
-- Status: DESIGNED. Applied cleanly to postgres:16 in a scratch container (see
-- docs/architecture/03-data-model.md §7). Becomes the first Alembic migration in Phase 1.
--
-- Conventions
--   * Primary keys are UUIDs; the application supplies time-ordered UUIDv7
--     (gen_random_uuid() default exists only as a fallback).
--   * LEDGER tables (append-only, hash-chained where noted): evidence, evidence_validity_events,
--     control_evaluations, finding_events, finding_risk_assessments, exception_events,
--     application_classifications, audit_events. INSERT-only grants + trigger guard.
--   * PROJECTION tables (current state, rebuildable from ledgers): control_states,
--     evidence_current_state, requirement_states, findings (status columns).
--   * High-volume ledgers are RANGE-partitioned monthly; partitions are created ahead by a
--     scheduled job (pg_partman or the platform scheduler) and DETACHED for retention.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS aap;
SET search_path = aap, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- -----------------------------------------------------------------------------
-- Roles (created by the migrator; NOLOGIN groups; real logins are Entra-mapped
-- managed identities granted membership)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_api')      THEN CREATE ROLE aap_api      NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_worker')   THEN CREATE ROLE aap_worker   NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aap_reporting') THEN CREATE ROLE aap_reporting NOLOGIN; END IF;
END $$;

-- -----------------------------------------------------------------------------
-- Enumerations
-- -----------------------------------------------------------------------------
CREATE TYPE lifecycle_status     AS ENUM ('proposed', 'development', 'pilot', 'production', 'deprecated', 'retired');
CREATE TYPE exposure_level       AS ENUM ('isolated', 'internal', 'partner', 'internet_authenticated', 'internet_public');
CREATE TYPE repo_role            AS ENUM ('primary', 'component', 'iac', 'library', 'documentation');
CREATE TYPE onboarding_status    AS ENUM ('discovered', 'onboarding_pr_open', 'onboarded', 'excluded');
CREATE TYPE env_type             AS ENUM ('development', 'test', 'staging', 'production', 'other');
CREATE TYPE cloud_provider       AS ENUM ('azure', 'aws', 'gcp', 'other');
CREATE TYPE cloud_scope_type     AS ENUM ('subscription', 'resource_group', 'account', 'organizational_unit', 'tag', 'project');
CREATE TYPE confidence_level     AS ENUM ('C0', 'C1', 'C2', 'C3', 'M1', 'M2');
CREATE TYPE producer_type        AS ENUM ('approved_workflow', 'platform_connector', 'manual', 'external_system');
CREATE TYPE evidence_result      AS ENUM ('pass', 'fail', 'findings', 'inconclusive', 'error', 'observed');
CREATE TYPE evidence_state       AS ENUM ('active', 'expiring', 'expired', 'superseded', 'revoked');
CREATE TYPE scope_type           AS ENUM ('application', 'repository', 'artifact', 'cloud_scope', 'environment', 'organisation');
CREATE TYPE control_state        AS ENUM ('satisfied', 'partial', 'not_satisfied', 'stale', 'no_evidence', 'excepted', 'not_applicable', 'error');
CREATE TYPE requirement_level    AS ENUM ('mandatory', 'recommended', 'n/a');
CREATE TYPE finding_type         AS ENUM ('code', 'dependency', 'secret', 'iac', 'container', 'dast', 'api', 'cloud',
                                          'malicious_package', 'licence', 'control_gap', 'pentest', 'architecture',
                                          'threat_model', 'exception_expired');
CREATE TYPE source_system        AS ENUM ('defectdojo', 'ghas', 'dependency_track', 'defender', 'security_hub', 'platform', 'manual', 'osv');
CREATE TYPE finding_status       AS ENUM ('new', 'triaged', 'ticketed', 'fix_pending', 'verified', 'closed',
                                          'false_positive', 'excepted', 'reopened');
CREATE TYPE priority_level       AS ENUM ('P1', 'P2', 'P3', 'P4');
CREATE TYPE exception_status     AS ENUM ('draft', 'pending_approval', 'approved', 'rejected', 'expired', 'revoked', 'closed');
CREATE TYPE exception_target     AS ENUM ('control', 'finding', 'requirement', 'sla');
CREATE TYPE assessment_type      AS ENUM ('samm_organisation', 'samm_application', 'architecture_review', 'threat_model_review',
                                          'pentest', 'manual_control', 'classification_review');
CREATE TYPE assessment_status    AS ENUM ('planned', 'in_progress', 'submitted', 'approved', 'rejected', 'cancelled');
CREATE TYPE requirement_status   AS ENUM ('verified', 'scanned_no_issues', 'failed', 'unverified', 'excepted', 'not_applicable');
CREATE TYPE sbom_format          AS ENUM ('cyclonedx', 'spdx');
CREATE TYPE component_scope      AS ENUM ('required', 'optional', 'development', 'unknown');
CREATE TYPE artifact_type        AS ENUM ('container_image', 'package', 'binary', 'other');
CREATE TYPE stride_category      AS ENUM ('spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege');
CREATE TYPE job_status           AS ENUM ('queued', 'running', 'succeeded', 'failed', 'dead');

-- -----------------------------------------------------------------------------
-- Ledger guard: blocks UPDATE/DELETE/TRUNCATE on append-only tables.
-- Retention removes data only by DETACH/DROP PARTITION, run by the migrator role.
-- -----------------------------------------------------------------------------
CREATE FUNCTION ledger_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only table %.%: % is not permitted', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE FUNCTION touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- =============================================================================
-- 1. Organisation, people, access
-- =============================================================================
CREATE TABLE org_units (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id       uuid REFERENCES org_units(id),
  unit_type       text NOT NULL CHECK (unit_type ~ '^[a-z][a-z0-9_]{1,31}$'),  -- a level from config/organization.yaml
  name            text NOT NULL,
  slug            text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{2,64}$'),
  scm_group       text,          -- e.g. 'github:acme/claims-team' or 'gitlab:acme/claims'; membership sync source
  idp_group_id    text,          -- the identity provider's group id for this unit (OIDC groups claim)
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
-- Exactly one root unit: the organization (its level name comes from config/organization.yaml).
CREATE UNIQUE INDEX org_units_single_root ON org_units ((true)) WHERE parent_id IS NULL;
CREATE INDEX org_units_parent_idx ON org_units (parent_id);

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name    text NOT NULL,
  email           text,
  active          boolean NOT NULL DEFAULT true,
  last_synced_at  timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Every identity a person has: one per identity provider (sign-in) and per source-control platform. Provider-neutral:
-- 'oidc:<issuer>' + subject for sign-in; 'github' / 'gitlab' + the platform's immutable user id (+ login) for SCM.
CREATE TABLE user_identities (
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider        text NOT NULL CHECK (provider ~ '^(oidc:.+|[a-z][a-z0-9_-]{1,31})$'),
  external_id     text NOT NULL,     -- OIDC subject / oid, or the SCM's numeric user id
  login           text,              -- SCM username (matched case-insensitively), or the IdP's preferred username
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, external_id)
);
-- SCM logins are unique per platform; an IdP's preferred_username is mutable and not guaranteed unique, so it is not.
CREATE UNIQUE INDEX user_identities_login_idx ON user_identities (provider, lower(login))
  WHERE login IS NOT NULL AND provider NOT LIKE 'oidc:%';
CREATE INDEX user_identities_user_idx ON user_identities (user_id);

CREATE TABLE org_unit_members (
  org_unit_id     uuid NOT NULL REFERENCES org_units(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source          text NOT NULL DEFAULT 'manual',  -- idp | scm | registry | manual
  synced_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_unit_id, user_id)
);
CREATE INDEX org_unit_members_user_idx ON org_unit_members (user_id);

-- Platform roles (ADR-013). Scope: whole org (both NULL), an org unit (and descendants), or an application.
CREATE TABLE role_assignments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_type  text NOT NULL CHECK (principal_type IN ('user', 'idp_group')),
  principal_id    text NOT NULL,
  role            text NOT NULL CHECK (role IN ('platform_admin', 'security_leadership', 'appsec_engineer', 'governance_analyst',
                                                 'unit_lead', 'app_owner', 'engineer', 'champion', 'auditor', 'executive')),
  scope_org_unit_id   uuid REFERENCES org_units(id),
  scope_application_id uuid,  -- FK added after applications
  granted_by      uuid REFERENCES users(id),
  granted_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  CHECK (scope_org_unit_id IS NULL OR scope_application_id IS NULL)
);
CREATE INDEX role_assignments_principal_idx ON role_assignments (principal_type, principal_id);

-- =============================================================================
-- 2. Application registry
-- =============================================================================
CREATE SEQUENCE application_key_seq;

CREATE TABLE applications (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_key             text NOT NULL UNIQUE DEFAULT ('APP-' || lpad(nextval('application_key_seq')::text, 5, '0')),
  name                text NOT NULL,
  description         text,
  org_unit_id         uuid NOT NULL REFERENCES org_units(id),       -- owning team
  business_owner_id   uuid REFERENCES users(id),
  technical_owner_id  uuid REFERENCES users(id),
  champion_id         uuid REFERENCES users(id),
  lifecycle           lifecycle_status NOT NULL DEFAULT 'development',
  exposure            exposure_level,
  data_classification text,          -- label from config/profiles/<profile>/classification.yaml (not an enum: configurable)
  personal_data       text,
  tier_rank           smallint CHECK (tier_rank BETWEEN 1 AND 9),   -- current approved tier
  classification_id   uuid,          -- FK added after application_classifications
  profile             jsonb NOT NULL DEFAULT '{}'::jsonb,  -- tech stack, capability flags, regulatory, distribution
  source_repo_id      uuid,          -- repo whose .security/application.yaml is authoritative
  source_commit_sha   text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  retired_at          timestamptz
);
CREATE INDEX applications_org_unit_idx ON applications (org_unit_id);
CREATE INDEX applications_tier_idx ON applications (tier_rank) WHERE lifecycle <> 'retired';
CREATE INDEX applications_name_trgm ON applications USING gin (name gin_trgm_ops);
CREATE INDEX applications_profile_gin ON applications USING gin (profile jsonb_path_ops);
CREATE TRIGGER applications_touch BEFORE UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

ALTER TABLE role_assignments
  ADD CONSTRAINT role_assignments_app_fk FOREIGN KEY (scope_application_id) REFERENCES applications(id);

-- Full snapshot on every registry change (who, what, from which application.yaml commit)
CREATE TABLE application_revisions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id  uuid NOT NULL REFERENCES applications(id),
  revision        integer NOT NULL,
  snapshot        jsonb NOT NULL,
  changed_fields  text[] NOT NULL DEFAULT '{}',
  source          text NOT NULL CHECK (source IN ('application_yaml', 'ui', 'api', 'discovery', 'migration')),
  source_commit_sha text,
  actor_id        uuid REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (application_id, revision)
);

CREATE TABLE application_classifications (           -- LEDGER
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid NOT NULL REFERENCES applications(id),
  model_version       text NOT NULL,                  -- config_versions.version of classification model
  inputs              jsonb NOT NULL,
  matched_floor_rules text[] NOT NULL DEFAULT '{}',
  points              integer NOT NULL,
  computed_tier       smallint NOT NULL,
  requested_tier      smallint,                       -- if owner requests an override
  override_reason     text,
  decision            text NOT NULL CHECK (decision IN ('auto_approved', 'pending', 'approved', 'rejected')),
  decided_by          uuid REFERENCES users(id),
  decided_at          timestamptz,
  supersedes_id       uuid REFERENCES application_classifications(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  CHECK (requested_tier IS NULL OR override_reason IS NOT NULL)
);
CREATE INDEX app_class_app_idx ON application_classifications (application_id, created_at DESC);
ALTER TABLE applications
  ADD CONSTRAINT applications_classification_fk FOREIGN KEY (classification_id) REFERENCES application_classifications(id);

CREATE TABLE environments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  name            text NOT NULL,
  env_type        env_type NOT NULL,
  url             text,
  scm_environment text,          -- the deployment environment's name in the SCM (GitHub environment / GitLab environment)
  UNIQUE (application_id, name)
);

CREATE TABLE cloud_scopes (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  environment_id  uuid REFERENCES environments(id),
  provider        cloud_provider NOT NULL,
  scope_type      cloud_scope_type NOT NULL,
  scope_ref       text NOT NULL,              -- subscription id / RG resource id / account id / tag k=v
  verified_at     timestamptz,                -- last time discovery confirmed the scope exists
  UNIQUE (provider, scope_type, scope_ref, application_id)
);
CREATE INDEX cloud_scopes_ref_idx ON cloud_scopes (provider, scope_ref);

-- Data stores, APIs, images, queues, service URLs ("assets")
CREATE TABLE application_assets (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  asset_type      text NOT NULL CHECK (asset_type IN ('data_store', 'api', 'container_image', 'service_url', 'queue', 'function', 'other')),
  name            text NOT NULL,
  ref             text,
  classification  text,
  attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (application_id, asset_type, name)
);

CREATE TABLE application_dependencies (
  application_id      uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  depends_on_id       uuid NOT NULL REFERENCES applications(id),
  relationship        text NOT NULL DEFAULT 'calls',
  PRIMARY KEY (application_id, depends_on_id),
  CHECK (application_id <> depends_on_id)
);

CREATE TABLE third_party_services (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  name            text NOT NULL,
  supplier        text,
  data_shared     text,
  assurance_ref   text,
  UNIQUE (application_id, name)
);

-- =============================================================================
-- 3. Source, pipelines, artifacts, deployments
-- =============================================================================
CREATE TABLE repositories (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider        text NOT NULL CHECK (provider IN ('github', 'gitlab')),
  external_id     text NOT NULL,              -- the platform's immutable id: stable across renames/transfers
  external_node_id text,                      -- GitHub node id / GitLab global id, when available
  full_name       text NOT NULL,              -- owner/repo or group/subgroup/project (display; changes on rename)
  visibility      text NOT NULL CHECK (visibility IN ('public', 'private', 'internal')),
  default_branch  text NOT NULL,
  archived        boolean NOT NULL DEFAULT false,
  languages       jsonb NOT NULL DEFAULT '{}'::jsonb,
  topics          text[] NOT NULL DEFAULT '{}',
  onboarding      onboarding_status NOT NULL DEFAULT 'discovered',
  pushed_at       timestamptz,
  discovered_at   timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX repositories_external_idx ON repositories (provider, external_id);
CREATE INDEX repositories_full_name_trgm ON repositories USING gin (full_name gin_trgm_ops);
CREATE INDEX repositories_onboarding_idx ON repositories (onboarding) WHERE NOT archived;
CREATE TRIGGER repositories_touch BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

ALTER TABLE applications
  ADD CONSTRAINT applications_source_repo_fk FOREIGN KEY (source_repo_id) REFERENCES repositories(id);

CREATE TABLE application_repositories (
  application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  repository_id   uuid NOT NULL REFERENCES repositories(id),
  role            repo_role NOT NULL DEFAULT 'component',
  linked_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, repository_id)
);
CREATE INDEX app_repos_repo_idx ON application_repositories (repository_id);

CREATE TABLE pipelines (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id   uuid NOT NULL REFERENCES repositories(id),
  external_id     text NOT NULL,              -- workflow id (GitHub) / CI config path (GitLab)
  path            text NOT NULL,
  name            text,
  state           text,
  UNIQUE (repository_id, external_id)
);

CREATE TABLE pipeline_runs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  pipeline_id         uuid NOT NULL REFERENCES pipelines(id),
  external_run_id     text NOT NULL,          -- workflow run id (GitHub) / pipeline id (GitLab)
  run_attempt         integer NOT NULL DEFAULT 1,
  head_sha            text NOT NULL CHECK (head_sha ~ '^[0-9a-f]{40}$'),
  head_branch         text,
  event               text NOT NULL,
  conclusion          text,
  referenced_workflows jsonb NOT NULL DEFAULT '[]'::jsonb,
  started_at          timestamptz,
  completed_at        timestamptz,
  UNIQUE (pipeline_id, external_run_id, run_attempt)
);
CREATE INDEX pipeline_runs_pipeline_idx ON pipeline_runs (pipeline_id, completed_at DESC);
CREATE INDEX pipeline_runs_sha_idx ON pipeline_runs (head_sha);

CREATE TABLE artifacts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id   uuid REFERENCES repositories(id),
  artifact_type   artifact_type NOT NULL,
  name            text NOT NULL,                 -- e.g. myacr.azurecr.io/claims-api
  digest          text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  built_at        timestamptz,
  pipeline_run_id uuid REFERENCES pipeline_runs(id),
  UNIQUE (name, digest)
);
CREATE INDEX artifacts_digest_idx ON artifacts (digest);

CREATE TABLE deployments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id     uuid NOT NULL REFERENCES artifacts(id),
  environment_id  uuid NOT NULL REFERENCES environments(id),
  deployed_at     timestamptz NOT NULL,
  undeployed_at   timestamptz,
  evidence_id     uuid,                          -- deploy.record evidence (no FK: partitioned table)
  source          text NOT NULL                  -- scm_deployments | deploy_evidence | cloud_inventory
);
CREATE INDEX deployments_env_current_idx ON deployments (environment_id) WHERE undeployed_at IS NULL;
CREATE INDEX deployments_artifact_idx ON deployments (artifact_id);

-- =============================================================================
-- 4. Configuration versions, frameworks, controls
-- =============================================================================
CREATE TABLE config_versions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            text NOT NULL CHECK (kind IN ('control_catalogue', 'risk_model', 'classification', 'evidence_types',
                                                'licence_policy', 'trusted_producers', 'maturity_methodology', 'samm_targets')),
  version         text NOT NULL,
  git_sha         text NOT NULL,
  content_sha256  bytea NOT NULL,
  content         jsonb NOT NULL,
  loaded_at       timestamptz NOT NULL DEFAULT now(),
  active          boolean NOT NULL DEFAULT false,
  UNIQUE (kind, version)
);
CREATE UNIQUE INDEX config_versions_one_active ON config_versions (kind) WHERE active;

CREATE TABLE frameworks (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  framework_key   text NOT NULL,                 -- samm | asvs | ssdf | csf | slsa | owasp-top10 | api-top10
  version         text NOT NULL,
  source_url      text NOT NULL,
  content_sha256  bytea NOT NULL,
  imported_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (framework_key, version)
);

CREATE TABLE framework_items (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  framework_id    uuid NOT NULL REFERENCES frameworks(id),
  item_key        text NOT NULL,                 -- I-SB-A, v5.0.0-6.2.1, PW.7.2, PR.PS-06
  parent_id       uuid REFERENCES framework_items(id),
  item_type       text NOT NULL CHECK (item_type IN ('business_function', 'practice', 'stream', 'activity', 'question',
                                                     'chapter', 'section', 'requirement', 'group', 'practice_group', 'task',
                                                     'function', 'category', 'subcategory')),
  level           smallint,
  title           text NOT NULL,
  official_text   text,                          -- verbatim from the official source; never edited
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (framework_id, item_key)
);
CREATE INDEX framework_items_parent_idx ON framework_items (parent_id);

CREATE TABLE controls (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  catalogue_version_id uuid NOT NULL REFERENCES config_versions(id),
  control_key         text NOT NULL CHECK (control_key ~ '^ASC-[A-Z]{2,3}-[0-9]{2}$'),
  title               text NOT NULL,
  domain              text NOT NULL,
  objective_type      text NOT NULL,
  assessment_mode     text NOT NULL CHECK (assessment_mode IN ('automated', 'hybrid', 'manual')),
  definition          jsonb NOT NULL,            -- full catalogue entry as loaded
  UNIQUE (catalogue_version_id, control_key)
);
CREATE INDEX controls_key_idx ON controls (control_key);

CREATE TABLE control_framework_mappings (
  control_id          uuid NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
  framework_item_id   uuid NOT NULL REFERENCES framework_items(id),
  level               smallint,
  relation            text NOT NULL DEFAULT 'contributes_to',
  PRIMARY KEY (control_id, framework_item_id)
);
CREATE INDEX cfm_item_idx ON control_framework_mappings (framework_item_id);

CREATE TABLE control_applicability (
  control_id          uuid NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
  tier_rank           smallint NOT NULL,
  requirement         requirement_level NOT NULL,
  conditions          text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (control_id, tier_rank)
);

-- =============================================================================
-- 5. Evidence ledger
-- =============================================================================
CREATE TABLE trusted_producers (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  producer_type   producer_type NOT NULL,
  producer_ref    text NOT NULL,                 -- workflow path@sha or connector id@version
  evidence_types  text[] NOT NULL,
  approved_at     timestamptz NOT NULL,
  retired_at      timestamptz,
  config_version_id uuid NOT NULL REFERENCES config_versions(id),
  UNIQUE (producer_type, producer_ref)
);

CREATE TABLE evidence (                                             -- LEDGER, hash-chained
  evidence_id       uuid NOT NULL,
  ingested_at       timestamptz NOT NULL DEFAULT now(),
  evidence_type     text NOT NULL,
  application_id    uuid,                        -- no FK on partitioned ledger; enforced in ingestion
  scope_type        scope_type NOT NULL,
  scope_ref         text NOT NULL,
  subject           jsonb NOT NULL,
  producer_type     producer_type NOT NULL,
  producer_ref      text NOT NULL,
  tool              text,
  tool_version      text,
  policy_ref        text,
  observed_at       timestamptz NOT NULL,
  result            evidence_result NOT NULL,
  summary           jsonb NOT NULL DEFAULT '{}'::jsonb,
  confidence        confidence_level NOT NULL,
  confidence_reasons text[] NOT NULL DEFAULT '{}',
  run_ref           jsonb,
  raw_location      text,
  raw_sha256        bytea[] NOT NULL DEFAULT '{}',
  attestation_ref   text,
  commit_sha        text GENERATED ALWAYS AS (subject->>'commit_sha') STORED,
  artifact_digest   text GENERATED ALWAYS AS (subject->>'artifact_digest') STORED,
  prev_hash         bytea,
  record_hash       bytea NOT NULL,
  PRIMARY KEY (evidence_id, ingested_at),
  CHECK (observed_at <= ingested_at + interval '5 minutes')
) PARTITION BY RANGE (ingested_at);

CREATE INDEX evidence_app_type_idx ON evidence (application_id, evidence_type, observed_at DESC);
CREATE INDEX evidence_scope_idx    ON evidence (scope_type, scope_ref, evidence_type, observed_at DESC);
CREATE INDEX evidence_commit_idx   ON evidence (commit_sha) WHERE commit_sha IS NOT NULL;
CREATE INDEX evidence_digest_idx   ON evidence (artifact_digest) WHERE artifact_digest IS NOT NULL;
CREATE INDEX evidence_tool_idx     ON evidence (tool, tool_version);   -- revocation sweeps

CREATE TRIGGER evidence_guard BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION ledger_guard();
CREATE TRIGGER evidence_guard_truncate BEFORE TRUNCATE ON evidence FOR EACH STATEMENT EXECUTE FUNCTION ledger_guard();

-- Freshness transitions (append-only) + current projection
CREATE TABLE evidence_validity_events (                             -- LEDGER
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_id     uuid NOT NULL,
  state           evidence_state NOT NULL,
  reason          text NOT NULL,
  related_ref     text,                          -- e.g. new HEAD sha, revocation rule id, event id
  occurred_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_validity_evidence_idx ON evidence_validity_events (evidence_id, occurred_at);
CREATE TRIGGER evidence_validity_guard BEFORE UPDATE OR DELETE ON evidence_validity_events FOR EACH ROW EXECUTE FUNCTION ledger_guard();

CREATE TABLE evidence_current_state (                               -- PROJECTION
  evidence_id     uuid PRIMARY KEY,
  application_id  uuid,
  evidence_type   text NOT NULL,
  scope_type      scope_type NOT NULL,
  scope_ref       text NOT NULL,
  state           evidence_state NOT NULL,
  confidence      confidence_level NOT NULL,
  observed_at     timestamptz NOT NULL,
  valid_until     timestamptz,
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ecs_lookup_idx ON evidence_current_state (application_id, evidence_type, scope_ref) WHERE state IN ('active', 'expiring');
CREATE INDEX ecs_expiry_idx ON evidence_current_state (valid_until) WHERE state IN ('active', 'expiring');

CREATE TABLE evidence_rejections (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  received_at     timestamptz NOT NULL DEFAULT now(),
  repository_provider text,
  repository_external_id text,
  run_id          bigint,
  reason_code     text NOT NULL CHECK (reason_code IN ('UNTRUSTED_PRODUCER', 'UNAPPROVED_WORKFLOW_REF', 'ATTESTATION_INVALID',
                                                       'DIGEST_MISMATCH', 'BINDING_MISMATCH', 'REJECTED_SIZE', 'SCHEMA_INVALID', 'OTHER')),
  details         jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX evidence_rejections_repo_idx ON evidence_rejections (repository_provider, repository_external_id, received_at DESC);

CREATE TABLE evidence_checkpoints (
  chain_name      text NOT NULL,                 -- e.g. evidence_2026_10
  checkpoint_at   timestamptz NOT NULL,
  last_record_hash bytea NOT NULL,
  record_count    bigint NOT NULL,
  blob_uri        text NOT NULL,
  PRIMARY KEY (chain_name, checkpoint_at)
);

-- Documented explanations for chain anomalies (e.g. a canonicalisation bug). Hashes are NEVER rewritten;
-- an annotation records the affected range and its cause (runbook: evidence-integrity-mismatch).
CREATE TABLE chain_annotations (                                    -- LEDGER
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_name      text NOT NULL,
  first_record    uuid NOT NULL,
  last_record     uuid NOT NULL,
  cause           text NOT NULL CHECK (cause IN ('code_defect', 'corruption_restored', 'tampering_investigated', 'other')),
  description     text NOT NULL,
  incident_ref    text NOT NULL,
  recorded_by     uuid NOT NULL REFERENCES users(id),
  approved_by     uuid NOT NULL REFERENCES users(id),
  recorded_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (recorded_by <> approved_by)
);
CREATE TRIGGER chain_annotations_guard BEFORE UPDATE OR DELETE ON chain_annotations FOR EACH ROW EXECUTE FUNCTION ledger_guard();

-- =============================================================================
-- 6. Control evaluation
-- =============================================================================
CREATE TABLE control_evaluations (                                  -- LEDGER
  id                  uuid NOT NULL,
  evaluated_at        timestamptz NOT NULL DEFAULT now(),
  application_id      uuid NOT NULL,
  control_key         text NOT NULL,
  control_id          uuid NOT NULL,             -- controls row for the catalogue version used
  scope_type          scope_type NOT NULL,
  scope_ref           text NOT NULL,
  state               control_state NOT NULL,
  previous_state      control_state,
  evaluator           text NOT NULL,             -- scan_executed@1
  evaluator_build     text NOT NULL,             -- platform build (image digest) that ran it
  catalogue_version_id uuid NOT NULL,
  evidence_ids        uuid[] NOT NULL DEFAULT '{}',
  explanation         text NOT NULL,
  details             jsonb NOT NULL DEFAULT '{}'::jsonb,
  observe_mode        boolean NOT NULL DEFAULT false,   -- grace period: computed but not enforced
  PRIMARY KEY (id, evaluated_at)
) PARTITION BY RANGE (evaluated_at);
CREATE INDEX control_eval_lookup_idx ON control_evaluations (application_id, control_key, evaluated_at DESC);
CREATE TRIGGER control_evaluations_guard BEFORE UPDATE OR DELETE ON control_evaluations FOR EACH ROW EXECUTE FUNCTION ledger_guard();

CREATE TABLE control_states (                                       -- PROJECTION
  application_id      uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  control_key         text NOT NULL,
  scope_type          scope_type NOT NULL,
  scope_ref           text NOT NULL,
  requirement         requirement_level NOT NULL,
  state               control_state NOT NULL,
  since               timestamptz NOT NULL,
  last_evaluation_id  uuid NOT NULL,
  last_evaluated_at   timestamptz NOT NULL,
  observe_mode        boolean NOT NULL DEFAULT false,
  PRIMARY KEY (application_id, control_key, scope_type, scope_ref)
);
CREATE INDEX control_states_gap_idx ON control_states (control_key, state) WHERE requirement = 'mandatory';

-- =============================================================================
-- 7. Assessments, maturity, requirements
-- =============================================================================
CREATE TABLE assessments (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_type     assessment_type NOT NULL,
  application_id      uuid REFERENCES applications(id),
  org_unit_id         uuid REFERENCES org_units(id),
  status              assessment_status NOT NULL DEFAULT 'planned',
  scope               jsonb NOT NULL DEFAULT '{}'::jsonb,
  lead_assessor_id    uuid REFERENCES users(id),
  approved_by         uuid REFERENCES users(id),
  due_at              timestamptz,
  started_at          timestamptz,
  submitted_at        timestamptz,
  approved_at         timestamptz,
  evidence_id         uuid,                      -- evidence record created on approval
  CHECK (application_id IS NOT NULL OR org_unit_id IS NOT NULL),
  CHECK (approved_by IS NULL OR approved_by <> lead_assessor_id)   -- SoD (also enforced in service layer)
);
CREATE INDEX assessments_app_idx ON assessments (application_id, assessment_type, approved_at DESC);
CREATE INDEX assessments_due_idx ON assessments (due_at) WHERE status IN ('planned', 'in_progress');

CREATE TABLE assessment_answers (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id       uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  framework_item_id   uuid NOT NULL REFERENCES framework_items(id),
  answer_value        numeric(3,2) NOT NULL CHECK (answer_value BETWEEN 0 AND 1),
  rationale           text,
  evidence_refs       text[] NOT NULL DEFAULT '{}',
  answered_by         uuid NOT NULL REFERENCES users(id),
  answered_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (assessment_id, framework_item_id)
);

CREATE TABLE architecture_reviews (
  assessment_id       uuid PRIMARY KEY REFERENCES assessments(id),
  design_commit_sha   text,
  outcome             text NOT NULL CHECK (outcome IN ('approved', 'approved_with_conditions', 'rejected')),
  conditions          text,
  material_change_ref text
);

CREATE TABLE security_tests (                    -- scheduled / planned tests (pen test, DAST config)
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  test_type           text NOT NULL CHECK (test_type IN ('pentest', 'dast', 'api_scan', 'red_team', 'code_review')),
  environment_id      uuid REFERENCES environments(id),
  cadence_days        integer,
  next_due_at         timestamptz,
  last_evidence_id    uuid,
  config              jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE maturity_snapshots (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  period              date NOT NULL UNIQUE,         -- first day of month
  taken_at            timestamptz NOT NULL DEFAULT now(),
  catalogue_version_id uuid NOT NULL REFERENCES config_versions(id),
  methodology_version_id uuid NOT NULL REFERENCES config_versions(id),
  published           boolean NOT NULL DEFAULT false
);

CREATE TABLE maturity_scores (
  snapshot_id         uuid NOT NULL REFERENCES maturity_snapshots(id),
  scope_type          scope_type NOT NULL CHECK (scope_type IN ('application', 'organisation')),
  scope_id            uuid NOT NULL,              -- application id or org unit id
  framework_item_id   uuid NOT NULL REFERENCES framework_items(id),   -- stream / practice / business function
  score               numeric(4,2) NOT NULL CHECK (score BETWEEN 0 AND 3),
  automated_pct       numeric(5,2) NOT NULL,
  manual_independent_pct numeric(5,2) NOT NULL,
  manual_self_pct     numeric(5,2) NOT NULL,
  unassessed_pct      numeric(5,2) NOT NULL,
  PRIMARY KEY (snapshot_id, scope_type, scope_id, framework_item_id)
);

CREATE TABLE maturity_targets (                  -- "maturity_levels": target profile per tier
  tier_rank           smallint NOT NULL,
  framework_item_id   uuid NOT NULL REFERENCES framework_items(id),
  target_score        numeric(4,2) NOT NULL,
  config_version_id   uuid NOT NULL REFERENCES config_versions(id),
  PRIMARY KEY (tier_rank, framework_item_id, config_version_id)
);

CREATE TABLE security_requirements (             -- per-application instantiated requirements
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  framework_item_id   uuid REFERENCES framework_items(id),   -- ASVS requirement, if from ASVS
  requirement_key     text NOT NULL,             -- v5.0.0-6.2.1 or CUSTOM-xx
  source              text NOT NULL CHECK (source IN ('asvs', 'threat_model', 'regulatory', 'custom')),
  title               text NOT NULL,
  applicable          boolean NOT NULL DEFAULT true,
  na_justification    text,
  na_approved_by      uuid REFERENCES users(id),
  UNIQUE (application_id, requirement_key),
  CHECK (applicable OR na_justification IS NOT NULL)
);

CREATE TABLE requirement_states (                                   -- PROJECTION
  security_requirement_id uuid PRIMARY KEY REFERENCES security_requirements(id) ON DELETE CASCADE,
  status              requirement_status NOT NULL,
  method              text,
  evidence_ids        uuid[] NOT NULL DEFAULT '{}',
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- 8. Threat models
-- =============================================================================
CREATE TABLE threat_models (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid NOT NULL REFERENCES applications(id),
  repository_id       uuid NOT NULL REFERENCES repositories(id),
  commit_sha          text NOT NULL,
  methodology         text NOT NULL DEFAULT 'stride',
  schema_valid        boolean NOT NULL,
  validation_errors   jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary             jsonb NOT NULL DEFAULT '{}'::jsonb,
  evidence_id         uuid,
  parsed_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (repository_id, commit_sha)
);

CREATE TABLE threats (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  threat_model_id     uuid NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
  threat_key          text NOT NULL,             -- TM-07 (stable across versions)
  stride              stride_category[] NOT NULL,
  title               text NOT NULL,
  rating              text NOT NULL CHECK (rating IN ('low', 'medium', 'high', 'critical')),
  status              text NOT NULL CHECK (status IN ('open', 'mitigated', 'accepted', 'transferred')),
  UNIQUE (threat_model_id, threat_key)
);

CREATE TABLE mitigations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  threat_id           uuid NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
  ref_type            text NOT NULL CHECK (ref_type IN ('control', 'requirement', 'ticket', 'exception', 'test', 'description')),
  ref                 text NOT NULL,
  resolved            boolean NOT NULL DEFAULT false     -- ref exists in the platform
);

-- =============================================================================
-- 9. Vulnerability intelligence, components, SBOMs
-- =============================================================================
CREATE TABLE vulnerabilities (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vuln_key            text NOT NULL UNIQUE,      -- CVE-2026-1234 | GHSA-xxxx | MAL-2026-1 | OSV id
  aliases             text[] NOT NULL DEFAULT '{}',
  title               text,
  description         text,
  cwe_ids             integer[] NOT NULL DEFAULT '{}',
  cvss_v3_vector      text,
  cvss_v3_score       numeric(3,1),
  cvss_v4_vector      text,
  cvss_v4_score       numeric(3,1),
  epss_score          numeric(6,5),
  epss_percentile     numeric(6,5),
  epss_date           date,
  in_kev              boolean NOT NULL DEFAULT false,
  kev_added_at        date,
  exploit_public      boolean NOT NULL DEFAULT false,
  is_malicious        boolean NOT NULL DEFAULT false,
  published_at        timestamptz,
  modified_at         timestamptz,
  synced_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vulnerabilities_aliases_gin ON vulnerabilities USING gin (aliases);
CREATE INDEX vulnerabilities_kev_idx ON vulnerabilities (kev_added_at DESC) WHERE in_kev;

CREATE TABLE components (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  purl                text NOT NULL UNIQUE,      -- canonical, version-qualified purl
  ecosystem           text NOT NULL,             -- npm, pypi, maven, golang, nuget, terraform, deb, apk ...
  namespace           text,
  name                text NOT NULL,
  version             text NOT NULL,
  licence_expression  text,                      -- SPDX expression
  eol_date            date
);
CREATE INDEX components_name_idx ON components (ecosystem, namespace, name);
CREATE INDEX components_name_trgm ON components USING gin (name gin_trgm_ops);

CREATE TABLE component_vulnerabilities (
  component_id        uuid NOT NULL REFERENCES components(id),
  vulnerability_id    uuid NOT NULL REFERENCES vulnerabilities(id),
  fixed_versions      text[] NOT NULL DEFAULT '{}',
  source              text NOT NULL,             -- dependency_track | osv | ghsa
  matched_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (component_id, vulnerability_id)
);
CREATE INDEX component_vulns_vuln_idx ON component_vulnerabilities (vulnerability_id);

CREATE TABLE sboms (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid REFERENCES applications(id),
  repository_id       uuid REFERENCES repositories(id),
  artifact_id         uuid REFERENCES artifacts(id),
  scope_key           text NOT NULL,             -- 'repo:<provider>:<external_id>' or 'artifact:<name>'
  commit_sha          text,
  format              sbom_format NOT NULL,
  spec_version        text NOT NULL,
  serial_number       text,
  component_count     integer NOT NULL,
  purl_coverage_pct   numeric(5,2),
  evidence_id         uuid NOT NULL,
  dtrack_project_uuid uuid,
  is_current          boolean NOT NULL DEFAULT true,
  generated_at        timestamptz NOT NULL,
  ingested_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (repository_id IS NOT NULL OR artifact_id IS NOT NULL)
);
CREATE UNIQUE INDEX sboms_one_current_per_scope ON sboms (scope_key) WHERE is_current;
CREATE INDEX sboms_app_idx ON sboms (application_id) WHERE is_current;

CREATE TABLE sbom_components (
  sbom_id             uuid NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  component_id        uuid NOT NULL REFERENCES components(id),
  is_direct           boolean,
  scope               component_scope NOT NULL DEFAULT 'unknown',
  PRIMARY KEY (sbom_id, component_id)
);
CREATE INDEX sbom_components_component_idx ON sbom_components (component_id);

CREATE TABLE dependencies (                     -- dependency graph edges within an SBOM
  sbom_id             uuid NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  parent_component_id uuid NOT NULL REFERENCES components(id),
  child_component_id  uuid NOT NULL REFERENCES components(id),
  PRIMARY KEY (sbom_id, parent_component_id, child_component_id)
);

-- =============================================================================
-- 10. Findings, risk, exceptions, tickets
-- =============================================================================
CREATE SEQUENCE exception_key_seq;

CREATE TABLE exceptions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  exception_key       text NOT NULL UNIQUE DEFAULT ('EX-' || lpad(nextval('exception_key_seq')::text, 6, '0')),
  application_id      uuid NOT NULL REFERENCES applications(id),
  target_type         exception_target NOT NULL,
  target_ref          text NOT NULL,             -- control_key | finding id | requirement key
  justification       text NOT NULL,
  risk_description    text NOT NULL,
  residual_priority   priority_level NOT NULL,
  compensating_controls text,
  remediation_plan    text NOT NULL,
  owner_id            uuid NOT NULL REFERENCES users(id),
  requested_by        uuid NOT NULL REFERENCES users(id),
  approver_id         uuid REFERENCES users(id),
  status              exception_status NOT NULL DEFAULT 'draft',
  created_at          timestamptz NOT NULL DEFAULT now(),
  approved_at         timestamptz,
  starts_at           timestamptz,
  expires_at          timestamptz,
  review_at           timestamptz,
  renewal_of          uuid REFERENCES exceptions(id),
  renewal_count       smallint NOT NULL DEFAULT 0,
  CHECK (approver_id IS NULL OR approver_id <> requested_by),        -- SoD
  CHECK (status NOT IN ('approved') OR (approver_id IS NOT NULL AND approved_at IS NOT NULL AND expires_at IS NOT NULL)),
  CHECK (expires_at IS NULL OR starts_at IS NULL OR expires_at > starts_at)
);
CREATE INDEX exceptions_app_idx ON exceptions (application_id, status);
CREATE INDEX exceptions_expiry_idx ON exceptions (expires_at) WHERE status = 'approved';

CREATE TABLE exception_events (                                     -- LEDGER
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  exception_id        uuid NOT NULL REFERENCES exceptions(id),
  event_type          text NOT NULL,             -- submitted, approved, rejected, expired, revoked, renewed, reviewed
  actor_id            uuid REFERENCES users(id),
  at                  timestamptz NOT NULL DEFAULT now(),
  details             jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TRIGGER exception_events_guard BEFORE UPDATE OR DELETE ON exception_events FOR EACH ROW EXECUTE FUNCTION ledger_guard();

CREATE TABLE tickets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  system              text NOT NULL DEFAULT 'jira',
  ticket_key          text NOT NULL,             -- e.g. APPSEC-1234
  dedup_key           text NOT NULL UNIQUE,      -- deterministic; see ADR-018
  application_id      uuid NOT NULL REFERENCES applications(id),
  external_status     text,
  url                 text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_synced_at      timestamptz,
  UNIQUE (system, ticket_key)
);

CREATE TABLE findings (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  fingerprint         text NOT NULL UNIQUE,      -- dedup identity; see data-model doc §4
  application_id      uuid NOT NULL REFERENCES applications(id),
  repository_id       uuid REFERENCES repositories(id),
  scope_type          scope_type NOT NULL,
  scope_ref           text NOT NULL,
  finding_type        finding_type NOT NULL,
  source_system       source_system NOT NULL,
  source_refs         jsonb NOT NULL DEFAULT '[]'::jsonb,   -- [{system, id}] e.g. DD finding id, GHAS alert number
  title               text NOT NULL,
  description         text,                      -- sanitised; never contains secret values
  cwe_id              integer,
  vulnerability_id    uuid REFERENCES vulnerabilities(id),
  component_id        uuid REFERENCES components(id),
  control_key         text,                      -- for control_gap findings
  location            jsonb NOT NULL DEFAULT '{}'::jsonb,
  tool_severity       text,
  status              finding_status NOT NULL DEFAULT 'new',
  priority            priority_level,
  risk_score          smallint CHECK (risk_score BETWEEN 1 AND 25),
  risk_assessment_id  uuid,
  first_seen_at       timestamptz NOT NULL,
  last_seen_at        timestamptz NOT NULL,
  last_seen_evidence_id uuid,
  triage_due_at       timestamptz,
  sla_due_at          timestamptz,
  sla_breached        boolean NOT NULL DEFAULT false,
  exception_id        uuid REFERENCES exceptions(id),
  closed_at           timestamptz,
  closure_evidence_id uuid,                      -- the re-scan that verified the fix
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CHECK (status <> 'closed' OR closure_evidence_id IS NOT NULL OR finding_type IN ('control_gap', 'exception_expired'))
);
CREATE INDEX findings_app_open_idx ON findings (application_id, priority) WHERE status NOT IN ('closed', 'false_positive');
CREATE INDEX findings_sla_idx ON findings (sla_due_at) WHERE status NOT IN ('closed', 'false_positive', 'excepted');
CREATE INDEX findings_vuln_idx ON findings (vulnerability_id) WHERE vulnerability_id IS NOT NULL;
CREATE INDEX findings_component_idx ON findings (component_id) WHERE component_id IS NOT NULL;
CREATE INDEX findings_type_status_idx ON findings (finding_type, status);
CREATE INDEX findings_title_trgm ON findings USING gin (title gin_trgm_ops);
CREATE TRIGGER findings_touch BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE finding_tickets (                   -- many findings → one ticket (e.g. one upgrade fixes 5 CVEs)
  finding_id          uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  ticket_id           uuid NOT NULL REFERENCES tickets(id),
  linked_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (finding_id, ticket_id)
);
CREATE INDEX finding_tickets_ticket_idx ON finding_tickets (ticket_id);

CREATE TABLE finding_events (                                       -- LEDGER
  id                  uuid NOT NULL,
  at                  timestamptz NOT NULL DEFAULT now(),
  finding_id          uuid NOT NULL,
  event_type          text NOT NULL,             -- detected, seen_again, status_changed, priority_changed, ticketed, verified, reopened
  from_status         finding_status,
  to_status           finding_status,
  actor_type          text NOT NULL CHECK (actor_type IN ('user', 'system')),
  actor_id            text,
  evidence_id         uuid,
  details             jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);
CREATE INDEX finding_events_finding_idx ON finding_events (finding_id, at);
CREATE TRIGGER finding_events_guard BEFORE UPDATE OR DELETE ON finding_events FOR EACH ROW EXECUTE FUNCTION ledger_guard();

CREATE TABLE finding_risk_assessments (                             -- LEDGER ("risks" for findings)
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id          uuid NOT NULL REFERENCES findings(id),
  model_version_id    uuid NOT NULL REFERENCES config_versions(id),
  inputs              jsonb NOT NULL,
  likelihood          smallint NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
  impact              smallint NOT NULL CHECK (impact BETWEEN 1 AND 5),
  score               smallint NOT NULL CHECK (score BETWEEN 1 AND 25),
  priority            priority_level NOT NULL,
  applied_rules       text[] NOT NULL DEFAULT '{}',
  explanation         text NOT NULL,
  manual_override     boolean NOT NULL DEFAULT false,
  override_reason     text,
  override_by         uuid REFERENCES users(id),
  computed_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (NOT manual_override OR (override_reason IS NOT NULL AND override_by IS NOT NULL))
);
CREATE INDEX fra_finding_idx ON finding_risk_assessments (finding_id, computed_at DESC);
CREATE TRIGGER fra_guard BEFORE UPDATE OR DELETE ON finding_risk_assessments FOR EACH ROW EXECUTE FUNCTION ledger_guard();

ALTER TABLE findings ADD CONSTRAINT findings_risk_fk FOREIGN KEY (risk_assessment_id) REFERENCES finding_risk_assessments(id);

CREATE TABLE risks (                             -- application risk register (residual risks, accepted risks)
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id      uuid NOT NULL REFERENCES applications(id),
  source              text NOT NULL CHECK (source IN ('threat_model', 'exception', 'architecture_review', 'pentest', 'manual')),
  source_ref          text,
  title               text NOT NULL,
  likelihood          smallint CHECK (likelihood BETWEEN 1 AND 5),
  impact              smallint CHECK (impact BETWEEN 1 AND 5),
  owner_id            uuid REFERENCES users(id),
  status              text NOT NULL CHECK (status IN ('open', 'accepted', 'mitigating', 'closed')),
  review_at           timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX risks_app_idx ON risks (application_id, status);

-- =============================================================================
-- 11. Security champions & training
-- =============================================================================
CREATE TABLE security_champions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES users(id),
  org_unit_id         uuid NOT NULL REFERENCES org_units(id),
  appointed_at        date NOT NULL,
  ended_at            date,
  time_allocation_pct smallint CHECK (time_allocation_pct BETWEEN 0 AND 100)
);
CREATE UNIQUE INDEX champions_active_idx ON security_champions (user_id, org_unit_id) WHERE ended_at IS NULL;

CREATE TABLE champion_activities (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  champion_id         uuid NOT NULL REFERENCES security_champions(id),
  activity_type       text NOT NULL CHECK (activity_type IN ('threat_model', 'security_review', 'triage', 'training_delivered',
                                                             'community_session', 'remediation_support')),
  application_id      uuid REFERENCES applications(id),
  ref                 text,
  occurred_at         timestamptz NOT NULL
);

CREATE TABLE training_records (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES users(id),
  course_key          text NOT NULL,
  completed_at        date NOT NULL,
  expires_at          date,
  source              text NOT NULL,             -- lms connector id | manual_import
  UNIQUE (user_id, course_key, completed_at)
);

-- =============================================================================
-- 12. Audit, jobs, outbox, webhooks
-- =============================================================================
CREATE TABLE audit_events (                                          -- LEDGER, hash-chained
  id                  uuid NOT NULL,
  at                  timestamptz NOT NULL DEFAULT now(),
  actor_type          text NOT NULL CHECK (actor_type IN ('user', 'service', 'system')),
  actor_id            text NOT NULL,
  action              text NOT NULL,             -- e.g. exception.approve, finding.mark_false_positive, export.findings
  target_type         text,
  target_id           text,
  application_id      uuid,
  outcome             text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  request_id          text,
  source_ip           inet,
  user_agent          text,
  details             jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash           bytea,
  record_hash         bytea NOT NULL,
  PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, at DESC);
CREATE INDEX audit_events_target_idx ON audit_events (target_type, target_id, at DESC);
CREATE TRIGGER audit_events_guard BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION ledger_guard();
CREATE TRIGGER audit_events_guard_truncate BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION ledger_guard();

CREATE TABLE outbox (                            -- transactional outbox (ADR-024)
  id                  bigserial PRIMARY KEY,
  topic               text NOT NULL,
  payload             jsonb NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  dispatched_at       timestamptz
);
CREATE INDEX outbox_pending_idx ON outbox (id) WHERE dispatched_at IS NULL;

CREATE TABLE jobs (                              -- PG-backed queue (ADR-024)
  id                  bigserial PRIMARY KEY,
  queue               text NOT NULL,
  payload             jsonb NOT NULL,
  dedup_key           text,
  status              job_status NOT NULL DEFAULT 'queued',
  run_at              timestamptz NOT NULL DEFAULT now(),
  attempts            integer NOT NULL DEFAULT 0,
  max_attempts        integer NOT NULL DEFAULT 8,
  locked_by           text,
  locked_until        timestamptz,
  last_error          text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  finished_at         timestamptz
);
CREATE INDEX jobs_ready_idx ON jobs (queue, run_at) WHERE status = 'queued';
CREATE UNIQUE INDEX jobs_dedup_idx ON jobs (queue, dedup_key) WHERE dedup_key IS NOT NULL AND status IN ('queued', 'running');

CREATE TABLE webhook_deliveries (                -- replay protection (24h+ retention)
  delivery_id         uuid PRIMARY KEY,
  event               text NOT NULL,
  received_at         timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- 13. Initial partitions (scheduler creates future months)
-- =============================================================================
DO $$
DECLARE
  m date := date_trunc('month', now())::date;
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['evidence', 'control_evaluations', 'finding_events', 'audit_events'] LOOP
    FOR i IN 0..2 LOOP
      EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                     t || '_' || to_char(m + (i || ' month')::interval, 'YYYY_MM'), t,
                     m + (i || ' month')::interval, m + ((i + 1) || ' month')::interval);
    END LOOP;
  END LOOP;
END $$;

-- =============================================================================
-- 14. Row-level security (defence in depth; the API enforces the same scoping)
-- Session settings set per request/transaction by the API:
--   aap.scope_all   = 'on' for org-wide roles (security_leadership, appsec_engineer, auditor, executive)
--   aap.org_units   = '{uuid,...}' expanded org units the caller may see
-- Workers run as aap_worker with BYPASSRLS-equivalent policy (they act for the platform, not a user).
-- =============================================================================
CREATE FUNCTION visible_application_ids() RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = aap, public AS $$
  SELECT CASE
    WHEN current_setting('aap.scope_all', true) = 'on' THEN NULL
    ELSE coalesce(
      (SELECT array_agg(a.id) FROM aap.applications a
        WHERE a.org_unit_id = ANY (coalesce(nullif(current_setting('aap.org_units', true), '')::uuid[], '{}'::uuid[]))),
      '{}'::uuid[])
  END
$$;

-- The scalar sub-select makes the planner evaluate the visible set once per statement (InitPlan), not per row.
CREATE FUNCTION app_visible(app uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT current_setting('aap.scope_all', true) = 'on' OR app = ANY ((SELECT aap.visible_application_ids())::uuid[])
$$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['findings', 'control_states', 'exceptions', 'sboms', 'risks', 'evidence_current_state',
                           'security_requirements', 'threat_models', 'tickets'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR ALL TO aap_api USING (app_visible(application_id)) WITH CHECK (app_visible(application_id))', t || '_scope', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR ALL TO aap_worker USING (true) WITH CHECK (true)', t || '_worker', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT TO aap_reporting USING (true)', t || '_reporting', t);
  END LOOP;
END $$;

ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
CREATE POLICY applications_scope ON applications FOR ALL TO aap_api
  USING (current_setting('aap.scope_all', true) = 'on'
         OR org_unit_id = ANY (coalesce(nullif(current_setting('aap.org_units', true), '')::uuid[], '{}'::uuid[])))
  WITH CHECK (current_setting('aap.scope_all', true) = 'on'
         OR org_unit_id = ANY (coalesce(nullif(current_setting('aap.org_units', true), '')::uuid[], '{}'::uuid[])));
CREATE POLICY applications_worker ON applications FOR ALL TO aap_worker USING (true) WITH CHECK (true);
CREATE POLICY applications_reporting ON applications FOR SELECT TO aap_reporting USING (true);

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_scope ON evidence FOR SELECT TO aap_api USING (application_id IS NULL OR app_visible(application_id));
CREATE POLICY evidence_worker_read ON evidence FOR SELECT TO aap_worker USING (true);
CREATE POLICY evidence_worker_insert ON evidence FOR INSERT TO aap_worker WITH CHECK (true);
CREATE POLICY evidence_reporting ON evidence FOR SELECT TO aap_reporting USING (true);

-- =============================================================================
-- 15. Grants: ledgers are INSERT/SELECT only. Nobody but the owner can UPDATE/DELETE them,
-- and the guard trigger blocks the owner too (superuser bypass is caught by the hash chain).
-- =============================================================================
GRANT USAGE ON SCHEMA aap TO aap_api, aap_worker, aap_reporting;
GRANT SELECT ON ALL TABLES IN SCHEMA aap TO aap_api, aap_worker, aap_reporting;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA aap TO aap_api, aap_worker;

-- Ledgers: insert only
GRANT INSERT ON evidence, evidence_validity_events, chain_annotations, control_evaluations, finding_events, finding_risk_assessments,
                exception_events, application_classifications, audit_events, application_revisions
  TO aap_worker;
GRANT INSERT ON audit_events, exception_events, application_classifications, finding_events, application_revisions TO aap_api;

-- Mutable registry/projection tables
GRANT INSERT, UPDATE ON applications, environments, cloud_scopes, application_assets, application_dependencies,
                       third_party_services, exceptions, assessments, assessment_answers, architecture_reviews,
                       security_requirements, security_champions, champion_activities, risks
  TO aap_api;
GRANT INSERT, UPDATE, DELETE ON applications, application_repositories, repositories, pipelines, pipeline_runs, artifacts,
                               deployments, environments, cloud_scopes, application_assets, evidence_current_state,
                               evidence_rejections, evidence_checkpoints, control_states, findings, finding_tickets,
                               tickets, vulnerabilities, components, component_vulnerabilities, sboms, sbom_components,
                               dependencies, threat_models, threats, mitigations, requirement_states, maturity_snapshots,
                               maturity_scores, training_records, users, user_identities, org_units, org_unit_members, outbox, jobs,
                               webhook_deliveries, exceptions, assessments, security_tests, trusted_producers,
                               config_versions, frameworks, framework_items, controls, control_framework_mappings,
                               control_applicability, maturity_targets
  TO aap_worker;
GRANT EXECUTE ON FUNCTION visible_application_ids(), app_visible(uuid) TO aap_api, aap_worker, aap_reporting;

-- Partitions do NOT inherit the parent's RLS policies: a role able to SELECT a partition directly would
-- bypass row-level security. Revoke all direct partition access; access is only via the parent tables.
-- The partition-maintenance job must apply the same revoke to every partition it creates.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'aap' AND c.relkind = 'r' LOOP
    EXECUTE format('REVOKE ALL ON aap.%I FROM aap_api, aap_worker, aap_reporting', r.relname);
  END LOOP;
END $$;
