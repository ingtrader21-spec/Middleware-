BEGIN;

ALTER TABLE middleware_commands
    ADD COLUMN IF NOT EXISTS resource_version bigint NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS cancelled_at timestamptz,
    ADD COLUMN IF NOT EXISTS cancellation_reason text,
    ADD COLUMN IF NOT EXISTS reconciliation_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS reconciliation_reason text;

ALTER TABLE middleware_commands DROP CONSTRAINT IF EXISTS middleware_commands_state_check;
ALTER TABLE middleware_commands ADD CONSTRAINT middleware_commands_state_check
    CHECK (state IN (
        'persisted', 'queued', 'dispatching', 'accepted',
        'readback_pending', 'completed', 'failed',
        'reconciliation_required', 'dead_lettered', 'cancelled'
    ));

CREATE TABLE IF NOT EXISTS middleware_operation_mutations (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    command_id text NOT NULL,
    action text NOT NULL CHECK (action IN ('cancel', 'reconcile')),
    actor_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    response_status integer NOT NULL,
    response_payload jsonb NOT NULL CHECK (jsonb_typeof(response_payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, command_id)
        REFERENCES middleware_commands (tenant_id, command_id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, command_id, action, actor_id, idempotency_key)
);

DROP TRIGGER IF EXISTS middleware_operation_mutations_immutable ON middleware_operation_mutations;
CREATE TRIGGER middleware_operation_mutations_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_operation_mutations
FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

ALTER TABLE middleware_outbox
    ADD COLUMN IF NOT EXISTS command_id text,
    ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;

UPDATE middleware_outbox
SET command_id = payload->>'command_id'
WHERE command_id IS NULL
  AND jsonb_typeof(payload) = 'object'
  AND payload ? 'command_id';

CREATE INDEX IF NOT EXISTS middleware_outbox_command_pending_idx
    ON middleware_outbox (tenant_id, command_id, id)
    WHERE command_id IS NOT NULL
      AND completed_at IS NULL
      AND dead_lettered_at IS NULL
      AND reconciliation_required_at IS NULL
      AND cancelled_at IS NULL;

INSERT INTO middleware_schema_migrations (version, name)
VALUES (4, '0004_operation_control')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
