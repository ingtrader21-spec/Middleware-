BEGIN;
CREATE TABLE IF NOT EXISTS middleware_outbox_attempt_events (
  id bigserial PRIMARY KEY,
  outbox_id bigint NOT NULL REFERENCES middleware_outbox(id) ON DELETE RESTRICT,
  tenant_id text NOT NULL,
  attempt_number integer NOT NULL CHECK(attempt_number>0),
  event_type text NOT NULL CHECK(event_type IN ('claimed','completed','failed','unknown_outcome')),
  worker_id text NOT NULL,
  safe_error_code text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS middleware_outbox_attempt_events_lookup_idx ON middleware_outbox_attempt_events(tenant_id,outbox_id,attempt_number,id);
DROP TRIGGER IF EXISTS middleware_outbox_attempt_events_immutable ON middleware_outbox_attempt_events;
CREATE TRIGGER middleware_outbox_attempt_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_outbox_attempt_events FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();
INSERT INTO middleware_schema_migrations(version,name) VALUES(6,'0006_outbox_attempt_events') ON CONFLICT(version) DO UPDATE SET name=EXCLUDED.name;
COMMIT;
