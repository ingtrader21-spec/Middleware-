"""Durable Telnexa delivery callback inbox and analytics.

Revision ID: 0061_telnexa_delivery_events
Revises: 0060_agent_provisioning
"""

from alembic import op


revision = "0061_telnexa_delivery_events"
down_revision = "0060_agent_provisioning"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE telnexa_delivery_event_inbox (
      event_id text PRIMARY KEY,
      payload_hash char(64) NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
      received_at timestamptz NOT NULL DEFAULT now(),
      source text NOT NULL CHECK (source = 'telnexa'),
      event_version text NOT NULL CHECK (event_version = '1.0'),
      schema_version text NOT NULL CHECK (schema_version = '1.0'),
      "timestamp" bigint NOT NULL CHECK ("timestamp" > 0),
      occurred_at timestamptz NOT NULL,
      tenant_id text NOT NULL,
      correlation_id text NOT NULL,
      idempotency_key text NOT NULL,
      message_id uuid NOT NULL,
      provider_reference text,
      event_type text NOT NULL CHECK (event_type IN (
        'sms.message.delivered.v1',
        'sms.message.failed.v1',
        'sms.message.status.v1',
        'sms.message.reconciled.v1'
      )),
      status text NOT NULL CHECK (status IN (
        'accepted', 'queued', 'dispatched', 'delivered', 'failed',
        'cancelled', 'suppressed', 'expired', 'indeterminate'
      )),
      provider_status text NOT NULL,
      failure_code text,
      failure_message text,
      payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
      processing_status text NOT NULL DEFAULT 'pending' CHECK (
        processing_status IN ('pending', 'retry', 'complete', 'dead_letter')
      ),
      attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      last_error text,
      updated_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute(
        "CREATE INDEX ix_telnexa_delivery_inbox_state "
        "ON telnexa_delivery_event_inbox(processing_status,received_at)"
    )
    op.execute(
        "CREATE INDEX ix_telnexa_delivery_inbox_message "
        "ON telnexa_delivery_event_inbox(tenant_id,message_id,occurred_at)"
    )
    op.execute("""CREATE TABLE telnexa_delivery_analytics (
      event_id text PRIMARY KEY REFERENCES telnexa_delivery_event_inbox(event_id)
        ON DELETE RESTRICT,
      tenant_id text NOT NULL,
      message_id uuid NOT NULL,
      event_type text NOT NULL,
      status text NOT NULL,
      provider_status text NOT NULL,
      occurred_at timestamptz NOT NULL,
      received_at timestamptz NOT NULL DEFAULT now(),
      created_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute(
        "CREATE INDEX ix_telnexa_delivery_analytics_message "
        "ON telnexa_delivery_analytics(tenant_id,message_id,occurred_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE telnexa_delivery_analytics")
    op.execute("DROP TABLE telnexa_delivery_event_inbox")
