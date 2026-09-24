"""Add durable, ordered agent call events and authoritative state.

Revision ID: 0048_agent_call_realtime
Revises: 0047_breero_runtime_grants
"""

from alembic import op

revision = "0048_agent_call_realtime"
down_revision = "0047_breero_runtime_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE agent_call_state (
      call_id varchar(128) PRIMARY KEY,
      tenant_id varchar(128) NOT NULL,
      business_unit_id varchar(128) NOT NULL,
      campaign_id varchar(64) NOT NULL,
      agent_id varchar(128) NOT NULL,
      extension varchar(16) NOT NULL,
      correlation_id varchar(128) NOT NULL UNIQUE,
      asterisk_uniqueid varchar(128) NOT NULL,
      linkedid varchar(128) NOT NULL,
      event_type varchar(64) NOT NULL,
      state_rank integer NOT NULL,
      sequence bigint NOT NULL CHECK (sequence >= 0),
      event_timestamp timestamptz NOT NULL,
      context_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT uq_agent_call_state_extension_sequence UNIQUE(extension, sequence)
    )""")
    op.execute("CREATE INDEX ix_agent_call_state_tenant_id ON agent_call_state(tenant_id)")
    op.execute("CREATE INDEX ix_agent_call_state_extension ON agent_call_state(extension)")
    op.execute("""CREATE TABLE agent_call_event (
      id uuid PRIMARY KEY,
      schema_version varchar(16) NOT NULL,
      event_id varchar(128) NOT NULL UNIQUE,
      event_type varchar(64) NOT NULL,
      idempotency_key varchar(128) NOT NULL UNIQUE,
      correlation_id varchar(128) NOT NULL,
      call_id varchar(128) NOT NULL,
      tenant_id varchar(128) NOT NULL,
      business_unit_id varchar(128) NOT NULL,
      campaign_id varchar(64) NOT NULL,
      agent_id varchar(128) NOT NULL,
      extension varchar(16) NOT NULL,
      asterisk_uniqueid varchar(128) NOT NULL,
      linkedid varchar(128) NOT NULL,
      sequence bigint NOT NULL CHECK (sequence >= 0),
      event_timestamp timestamptz NOT NULL,
      payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      transition_applied boolean NOT NULL,
      recorded_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT uq_agent_call_event_call_sequence UNIQUE(call_id, sequence)
    )""")
    op.execute("CREATE INDEX ix_agent_call_event_call_id ON agent_call_event(call_id)")
    op.execute("CREATE INDEX ix_agent_call_event_extension ON agent_call_event(extension)")
    op.execute("""DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mw_integration_api') THEN
        GRANT SELECT, INSERT, UPDATE ON agent_call_state TO mw_integration_api;
        GRANT SELECT, INSERT ON agent_call_event TO mw_integration_api;
      END IF;
    END $$""")


def downgrade() -> None:
    op.execute("DROP TABLE agent_call_event")
    op.execute("DROP TABLE agent_call_state")
