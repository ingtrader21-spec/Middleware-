BEGIN;

CREATE TABLE IF NOT EXISTS middleware_commands (
    command_id text NOT NULL,
    tenant_id text NOT NULL,
    command_type text NOT NULL,
    command_version text NOT NULL,
    target text NOT NULL,
    requested_by text NOT NULL,
    correlation_id text NOT NULL,
    idempotency_key text NOT NULL,
    capability text NOT NULL,
    payload jsonb NOT NULL,
    payload_sha256 char(64) NOT NULL,
    state text NOT NULL,
    provider_operation_id text,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    queued_at timestamptz,
    accepted_at timestamptz,
    completed_at timestamptz,
    failed_at timestamptz,
    PRIMARY KEY (tenant_id, command_id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (command_version = '1.0'),
    CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (state IN (
        'persisted', 'queued', 'dispatching', 'accepted',
        'readback_pending', 'completed', 'failed',
        'reconciliation_required', 'dead_lettered'
    ))
);

CREATE INDEX IF NOT EXISTS middleware_commands_state_updated_idx
    ON middleware_commands (state, updated_at, tenant_id);

CREATE TABLE IF NOT EXISTS middleware_command_attempts (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    command_id text NOT NULL,
    attempt_number integer NOT NULL,
    state text NOT NULL,
    provider_operation_id text,
    result_payload jsonb,
    error_code text,
    error_detail text,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    UNIQUE (tenant_id, command_id, attempt_number),
    FOREIGN KEY (tenant_id, command_id)
        REFERENCES middleware_commands (tenant_id, command_id)
        ON DELETE RESTRICT,
    CHECK (attempt_number > 0),
    CHECK (result_payload IS NULL OR jsonb_typeof(result_payload) = 'object'),
    CHECK (state IN (
        'dispatching', 'accepted', 'readback_pending', 'completed',
        'failed', 'reconciliation_required'
    ))
);

CREATE TABLE IF NOT EXISTS middleware_command_audit (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    command_id text NOT NULL,
    previous_state text,
    new_state text NOT NULL,
    actor_id text NOT NULL,
    reason text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, command_id)
        REFERENCES middleware_commands (tenant_id, command_id)
        ON DELETE RESTRICT,
    CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS middleware_command_audit_lookup_idx
    ON middleware_command_audit (tenant_id, command_id, created_at, id);

INSERT INTO middleware_schema_migrations (version, name)
VALUES (2, '0002_command_ledger')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
