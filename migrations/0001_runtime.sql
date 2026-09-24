BEGIN;

CREATE TABLE IF NOT EXISTS middleware_schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS middleware_inbox (
    event_id text NOT NULL,
    tenant_id text NOT NULL,
    source_client_id text NOT NULL,
    event_type text NOT NULL,
    body_sha256 char(64) NOT NULL,
    semantic_sha256 char(64) NOT NULL,
    idempotency_key text NOT NULL,
    correlation_id text NOT NULL,
    payload jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status IN ('accepted', 'validated', 'rejected')),
    processed_at timestamptz,
    last_error text,
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS middleware_inbox_status_received_idx
    ON middleware_inbox (status, received_at);

CREATE TABLE IF NOT EXISTS middleware_outbox (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    destination text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    idempotency_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner text,
    lease_until timestamptz,
    completed_at timestamptz,
    dead_lettered_at timestamptz,
    reconciliation_required_at timestamptz,
    last_error text,
    UNIQUE (tenant_id, destination, idempotency_key)
);

CREATE INDEX IF NOT EXISTS middleware_outbox_dispatch_idx
    ON middleware_outbox (next_attempt_at, id)
    WHERE completed_at IS NULL
      AND dead_lettered_at IS NULL
      AND reconciliation_required_at IS NULL;

CREATE TABLE IF NOT EXISTS middleware_reconciliation_audit (
    id bigserial PRIMARY KEY,
    outbox_id bigint NOT NULL REFERENCES middleware_outbox(id) ON DELETE RESTRICT,
    tenant_id text NOT NULL,
    action text NOT NULL CHECK (action IN ('retry', 'complete', 'dead_letter')),
    operator_id text NOT NULL,
    reason text NOT NULL,
    attempt_count integer NOT NULL CHECK (attempt_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS middleware_reconciliation_audit_outbox_idx
    ON middleware_reconciliation_audit (outbox_id, created_at);

INSERT INTO middleware_schema_migrations (version, name)
VALUES (1, '0001_runtime')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
