BEGIN;

CREATE TABLE IF NOT EXISTS middleware_realtime_tickets (
    ticket_sha256 char(64) PRIMARY KEY,
    tenant_id text NOT NULL,
    campaign_id text NOT NULL,
    agent_id text NOT NULL,
    role text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (ticket_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (tenant_id <> '' AND campaign_id <> '' AND agent_id <> '' AND role <> '')
);

CREATE TABLE IF NOT EXISTS middleware_realtime_events (
    sequence bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    campaign_id text NOT NULL,
    agent_id text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    CHECK (event_type IN ('telephony.call-state.v1', 'telephony.screen-pop.v1'))
);

CREATE INDEX IF NOT EXISTS middleware_realtime_events_scope_sequence_idx
    ON middleware_realtime_events (tenant_id, campaign_id, agent_id, sequence);

INSERT INTO middleware_schema_migrations(version,name)
VALUES (10,'realtime_gateway') ON CONFLICT (version) DO NOTHING;

COMMIT;
