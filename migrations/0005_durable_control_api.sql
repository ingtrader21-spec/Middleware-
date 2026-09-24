BEGIN;

ALTER TABLE middleware_inbox
  ADD COLUMN IF NOT EXISTS resource_version bigint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS quarantined_at timestamptz,
  ADD COLUMN IF NOT EXISTS quarantine_reason text,
  ADD COLUMN IF NOT EXISTS released_at timestamptz,
  ADD COLUMN IF NOT EXISTS reprocess_requested_at timestamptz;

ALTER TABLE middleware_outbox
  ADD COLUMN IF NOT EXISTS resource_version bigint NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS middleware_control_mutations (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN ('inbox','outbox')),
  resource_id text NOT NULL,
  action text NOT NULL,
  actor_id text NOT NULL,
  api_version text NOT NULL DEFAULT 'v1' CHECK (api_version='v1'),
  idempotency_key text NOT NULL,
  request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
  response_status integer NOT NULL,
  response_payload jsonb NOT NULL CHECK (jsonb_typeof(response_payload)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, resource_kind, resource_id, action, actor_id, api_version, idempotency_key)
);

CREATE TABLE IF NOT EXISTS middleware_control_audit (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  resource_kind text NOT NULL,
  resource_id text NOT NULL,
  action text NOT NULL,
  actor_id text NOT NULL,
  reason text NOT NULL,
  previous_state text,
  new_state text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata)='object'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS middleware_control_audit_lookup_idx
  ON middleware_control_audit (tenant_id, resource_kind, resource_id, created_at, id);

DROP TRIGGER IF EXISTS middleware_control_mutations_immutable ON middleware_control_mutations;
CREATE TRIGGER middleware_control_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
ON middleware_control_mutations FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
DROP TRIGGER IF EXISTS middleware_control_audit_immutable ON middleware_control_audit;
CREATE TRIGGER middleware_control_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
ON middleware_control_audit FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

INSERT INTO middleware_schema_migrations(version,name) VALUES (5,'0005_durable_control_api')
ON CONFLICT(version) DO UPDATE SET name=EXCLUDED.name;
COMMIT;
