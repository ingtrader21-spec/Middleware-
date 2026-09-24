BEGIN;

CREATE TABLE IF NOT EXISTS middleware_observability_incidents (
  tenant_id text NOT NULL,
  incident_id uuid NOT NULL,
  alert_fingerprint text NOT NULL,
  group_key text NOT NULL,
  state text NOT NULL CHECK(state IN ('firing','acknowledged','resolved','inhibited','silenced')),
  severity text NOT NULL,
  service text NOT NULL,
  environment text NOT NULL,
  host text NOT NULL,
  labels jsonb NOT NULL CHECK(jsonb_typeof(labels)='object'),
  annotations jsonb NOT NULL CHECK(jsonb_typeof(annotations)='object'),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz,
  acknowledged_at timestamptz,
  acknowledged_by text,
  resolved_at timestamptz,
  source_deployment text NOT NULL,
  correlation_id text NOT NULL,
  resource_version bigint NOT NULL DEFAULT 1 CHECK(resource_version>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,incident_id),
  UNIQUE(tenant_id,alert_fingerprint)
);
CREATE INDEX IF NOT EXISTS middleware_observability_incidents_filter_idx
  ON middleware_observability_incidents(tenant_id,state,severity,service,updated_at DESC,incident_id DESC);

CREATE TABLE IF NOT EXISTS middleware_observability_incident_events (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  incident_id uuid NOT NULL,
  event_key text NOT NULL,
  request_idempotency_key text NOT NULL,
  event_type text NOT NULL CHECK(event_type IN ('firing','resolved','reopened','notification_repeat','notification_suppressed','acknowledge','resolve','reopen','inhibited','silenced')),
  previous_state text CHECK(previous_state IS NULL OR previous_state IN ('firing','acknowledged','resolved','inhibited','silenced')),
  new_state text NOT NULL CHECK(new_state IN ('firing','acknowledged','resolved','inhibited','silenced')),
  actor_id text NOT NULL,
  correlation_id text NOT NULL,
  source_deployment text NOT NULL,
  operation_id text,
  payload_sha256 char(64) NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
  safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(safe_metadata)='object'),
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(tenant_id,incident_id)
    REFERENCES middleware_observability_incidents(tenant_id,incident_id) ON DELETE RESTRICT,
  FOREIGN KEY(tenant_id,operation_id)
    REFERENCES middleware_commands(tenant_id,command_id) ON DELETE RESTRICT,
  UNIQUE(tenant_id,event_key),
  UNIQUE(tenant_id,request_idempotency_key)
);
CREATE INDEX IF NOT EXISTS middleware_observability_incident_events_timeline_idx
  ON middleware_observability_incident_events(tenant_id,incident_id,id);

CREATE TABLE IF NOT EXISTS middleware_observability_incident_audit (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  incident_id uuid NOT NULL,
  event_id bigint NOT NULL,
  action text NOT NULL,
  actor_id text NOT NULL,
  previous_state text,
  new_state text NOT NULL,
  correlation_id text NOT NULL,
  safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(safe_metadata)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(tenant_id,incident_id)
    REFERENCES middleware_observability_incidents(tenant_id,incident_id) ON DELETE RESTRICT,
  FOREIGN KEY(event_id)
    REFERENCES middleware_observability_incident_events(id) ON DELETE RESTRICT,
  UNIQUE(tenant_id,event_id)
);

CREATE TABLE IF NOT EXISTS middleware_observability_notification_intents (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  incident_id uuid NOT NULL,
  operation_id text NOT NULL,
  notification_class text NOT NULL CHECK(notification_class IN ('immediate','grouped')),
  idempotency_key text NOT NULL,
  scheduled_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(tenant_id,incident_id)
    REFERENCES middleware_observability_incidents(tenant_id,incident_id) ON DELETE RESTRICT,
  FOREIGN KEY(tenant_id,operation_id)
    REFERENCES middleware_commands(tenant_id,command_id) ON DELETE RESTRICT,
  UNIQUE(tenant_id,idempotency_key),
  UNIQUE(tenant_id,operation_id)
);

CREATE TABLE IF NOT EXISTS middleware_observability_incident_mutations (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  incident_id uuid NOT NULL,
  action text NOT NULL CHECK(action IN ('acknowledge','resolve','reopen')),
  actor_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_sha256 char(64) NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
  response_payload jsonb NOT NULL CHECK(jsonb_typeof(response_payload)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(tenant_id,incident_id)
    REFERENCES middleware_observability_incidents(tenant_id,incident_id) ON DELETE RESTRICT,
  UNIQUE(tenant_id,incident_id,action,actor_id,idempotency_key)
);

DROP TRIGGER IF EXISTS middleware_observability_incident_events_immutable
  ON middleware_observability_incident_events;
CREATE TRIGGER middleware_observability_incident_events_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_observability_incident_events
  FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

DROP TRIGGER IF EXISTS middleware_observability_incident_audit_immutable
  ON middleware_observability_incident_audit;
CREATE TRIGGER middleware_observability_incident_audit_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_observability_incident_audit
  FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

DROP TRIGGER IF EXISTS middleware_observability_incident_mutations_immutable
  ON middleware_observability_incident_mutations;
CREATE TRIGGER middleware_observability_incident_mutations_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_observability_incident_mutations
  FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

INSERT INTO middleware_schema_migrations(version,name)
VALUES(9,'0009_observability_incidents')
ON CONFLICT(version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
