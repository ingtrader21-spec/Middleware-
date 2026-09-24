BEGIN;
CREATE TABLE IF NOT EXISTS middleware_communication_messages (
  tenant_id text NOT NULL,
  message_id uuid NOT NULL,
  payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,message_id)
);
CREATE TABLE IF NOT EXISTS middleware_communication_events (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  event_id uuid NOT NULL,
  message_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL,
  payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
  UNIQUE(tenant_id,event_id),
  FOREIGN KEY(tenant_id,message_id) REFERENCES middleware_communication_messages(tenant_id,message_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS middleware_communication_events_timeline_idx ON middleware_communication_events(tenant_id,message_id,occurred_at,id);
CREATE TABLE IF NOT EXISTS middleware_communication_idempotency (
  tenant_id text NOT NULL, route text NOT NULL, idempotency_key text NOT NULL,
  request_sha256 char(64) NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
  message_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,route,idempotency_key),
  FOREIGN KEY(tenant_id,message_id) REFERENCES middleware_communication_messages(tenant_id,message_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS middleware_communication_provider_events (
  tenant_id text NOT NULL, provider_event_id text NOT NULL,
  request_sha256 char(64) NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,provider_event_id)
);
CREATE TABLE IF NOT EXISTS middleware_communication_suppressions (
  tenant_id text NOT NULL, channel text NOT NULL CHECK(channel IN ('email','sms')),
  subject text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,channel,subject)
);
CREATE TABLE IF NOT EXISTS middleware_communication_cancellations (
  tenant_id text NOT NULL, message_id uuid NOT NULL, idempotency_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,message_id,idempotency_key),
  FOREIGN KEY(tenant_id,message_id) REFERENCES middleware_communication_messages(tenant_id,message_id) ON DELETE RESTRICT
);
DROP TRIGGER IF EXISTS middleware_communication_events_immutable ON middleware_communication_events;
CREATE TRIGGER middleware_communication_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_communication_events FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
DROP TRIGGER IF EXISTS middleware_communication_idempotency_immutable ON middleware_communication_idempotency;
CREATE TRIGGER middleware_communication_idempotency_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_communication_idempotency FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
DROP TRIGGER IF EXISTS middleware_communication_provider_events_immutable ON middleware_communication_provider_events;
CREATE TRIGGER middleware_communication_provider_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_communication_provider_events FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
DROP TRIGGER IF EXISTS middleware_communication_cancellations_immutable ON middleware_communication_cancellations;
CREATE TRIGGER middleware_communication_cancellations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_communication_cancellations FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
INSERT INTO middleware_schema_migrations(version,name) VALUES(8,'0008_durable_communications') ON CONFLICT(version) DO UPDATE SET name=EXCLUDED.name;
COMMIT;
