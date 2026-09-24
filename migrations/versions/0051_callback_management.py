"""Professional callback registry and transactional event ledger.

Revision ID: 0051_callback_management
Revises: 0050_production_odoo_results
"""
from alembic import op

revision = "0051_callback_management"
down_revision = "0050_production_odoo_results"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("""CREATE TABLE callback_record (
      id uuid PRIMARY KEY, tenant_id varchar(128) NOT NULL, campaign_id varchar(128) NOT NULL,
      contact_id varchar(128), lead_id varchar(128), opportunity_id varchar(128),
      original_call_id varchar(128), original_linkedid varchar(128), assigned_agent_id varchar(128),
      assigned_team_id varchar(128), supervisor_id varchar(128), phone_number varchar(32) NOT NULL,
      normalized_phone varchar(32) NOT NULL, scheduled_at timestamptz NOT NULL, customer_timezone varchar(64) NOT NULL,
      priority varchar(16) NOT NULL DEFAULT 'NORMAL', reason varchar(256) NOT NULL, notes text NOT NULL DEFAULT '',
      state varchar(32) NOT NULL DEFAULT 'SCHEDULED', desired_state varchar(32) NOT NULL DEFAULT 'SCHEDULED',
      actual_state varchar(32) NOT NULL DEFAULT 'SCHEDULED', reminder_email_enabled boolean NOT NULL DEFAULT true,
      reminder_popup_enabled boolean NOT NULL DEFAULT true, email_reminder_1_at timestamptz, email_reminder_2_at timestamptz,
      popup_reminder_at timestamptz, attempt_count integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 3,
      last_attempt_at timestamptz, next_attempt_at timestamptz, completed_at timestamptz, cancelled_at timestamptz,
      completion_disposition varchar(64), completion_notes text, correlation_id varchar(128) NOT NULL,
      idempotency_key varchar(128) NOT NULL, request_hash varchar(64) NOT NULL, version integer NOT NULL DEFAULT 1,
      sync_state varchar(32) NOT NULL DEFAULT 'PENDING', compliance_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_by varchar(128) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_callback_owner CHECK (assigned_agent_id IS NOT NULL OR assigned_team_id IS NOT NULL),
      CONSTRAINT ck_callback_counters CHECK (version >= 1 AND attempt_count >= 0 AND max_attempts >= 1),
      CONSTRAINT uq_callback_tenant_idempotency UNIQUE(tenant_id,idempotency_key))""")
    op.execute("CREATE INDEX ix_callback_due_claim ON callback_record(state,scheduled_at)")
    op.execute("CREATE INDEX ix_callback_agent_queue ON callback_record(tenant_id,campaign_id,assigned_agent_id,scheduled_at)")
    op.execute("CREATE INDEX ix_callback_phone ON callback_record(tenant_id,normalized_phone)")
    op.execute("CREATE INDEX ix_callback_correlation ON callback_record(correlation_id)")
    op.execute("""CREATE TABLE callback_event (
      id uuid PRIMARY KEY, callback_id uuid NOT NULL REFERENCES callback_record(id) ON DELETE RESTRICT,
      tenant_id varchar(128) NOT NULL, campaign_id varchar(128) NOT NULL, event_type varchar(64) NOT NULL,
      version integer NOT NULL, idempotency_key varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL,
      actor_id varchar(128) NOT NULL, payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      published_at timestamptz, occurred_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT uq_callback_event_version_type UNIQUE(callback_id,version,event_type),
      CONSTRAINT uq_callback_event_idempotency UNIQUE(tenant_id,idempotency_key))""")
    op.execute("CREATE INDEX ix_callback_event_outbox ON callback_event(published_at,occurred_at)")
    op.execute("""CREATE TABLE callback_delivery (
      id uuid PRIMARY KEY, callback_id uuid NOT NULL REFERENCES callback_record(id) ON DELETE RESTRICT,
      callback_version integer NOT NULL, channel varchar(16) NOT NULL, stage varchar(32) NOT NULL,
      idempotency_key varchar(128) NOT NULL UNIQUE, status varchar(32) NOT NULL DEFAULT 'QUEUED',
      provider_message_id varchar(128), attempt_count integer NOT NULL DEFAULT 0, last_error_code varchar(64),
      next_attempt_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT uq_callback_delivery_stage UNIQUE(callback_id,callback_version,channel,stage))""")
    op.execute("CREATE INDEX ix_callback_delivery_retry ON callback_delivery(status,next_attempt_at)")
    op.execute("""DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mw_integration_api') THEN
      GRANT SELECT,INSERT,UPDATE ON callback_record TO mw_integration_api;
      GRANT SELECT,INSERT,UPDATE ON callback_event TO mw_integration_api;
      GRANT SELECT,INSERT,UPDATE ON callback_delivery TO mw_integration_api;
    END IF; END $$""")

def downgrade() -> None:
    op.execute("DROP TABLE callback_delivery")
    op.execute("DROP TABLE callback_event")
    op.execute("DROP TABLE callback_record")
