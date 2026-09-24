BEGIN;

CREATE TABLE IF NOT EXISTS middleware_event_ledger (
    ledger_id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    tenant_sequence bigint NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    event_version text NOT NULL,
    source_client_id text NOT NULL,
    correlation_id text NOT NULL,
    causation_id text NOT NULL,
    idempotency_key text NOT NULL,
    semantic_sha256 char(64) NOT NULL,
    previous_entry_hash char(64) NOT NULL,
    entry_hash char(64) NOT NULL,
    payload jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, tenant_sequence),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (tenant_sequence > 0),
    CHECK (event_version = '1.0'),
    CHECK (semantic_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (previous_entry_hash ~ '^[a-f0-9]{64}$'),
    CHECK (entry_hash ~ '^[a-f0-9]{64}$'),
    CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS middleware_event_ledger_event_type_idx
    ON middleware_event_ledger (event_type, recorded_at, ledger_id);

CREATE OR REPLACE FUNCTION middleware_reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only; % is prohibited', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS middleware_event_ledger_immutable
    ON middleware_event_ledger;
CREATE TRIGGER middleware_event_ledger_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_event_ledger
FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

DROP TRIGGER IF EXISTS middleware_command_audit_immutable
    ON middleware_command_audit;
CREATE TRIGGER middleware_command_audit_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_command_audit
FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

DROP TRIGGER IF EXISTS middleware_reconciliation_audit_immutable
    ON middleware_reconciliation_audit;
CREATE TRIGGER middleware_reconciliation_audit_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON middleware_reconciliation_audit
FOR EACH STATEMENT EXECUTE FUNCTION middleware_reject_immutable_mutation();

INSERT INTO middleware_schema_migrations (version, name)
VALUES (3, '0003_immutable_event_ledger')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
