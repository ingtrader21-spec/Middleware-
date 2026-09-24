"""Durable Klyrow delivery event inbox.

Revision ID: 0056_klyrow_delivery_events
Revises: 0055_klyrow_mail_inbound
"""

from alembic import op

revision = "0056_klyrow_delivery_events"
down_revision = "0055_klyrow_mail_inbound"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE klyrow_delivery_event_inbox (
      event_id text PRIMARY KEY,
      payload_hash char(64) NOT NULL,
      received_at timestamptz NOT NULL,
      source text NOT NULL CHECK (source='klyrow'),
      schema_version text NOT NULL,
      tenant_id text NOT NULL,
      message_id text NOT NULL,
      provider_message_id text NOT NULL,
      event_type text NOT NULL,
      correlation_id text NOT NULL,
      payload jsonb NOT NULL,
      status text NOT NULL CHECK (status IN ('pending','processing','complete','retry','dead_letter')),
      attempts integer NOT NULL DEFAULT 0,
      last_error text,
      updated_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute("CREATE INDEX ix_klyrow_delivery_inbox_state ON klyrow_delivery_event_inbox(status,received_at)")
    op.execute("""CREATE TABLE klyrow_delivery_analytics (
      event_id text PRIMARY KEY REFERENCES klyrow_delivery_event_inbox(event_id),
      tenant_id text NOT NULL,
      message_id text NOT NULL,
      event_type text NOT NULL,
      occurred_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    )""")


def downgrade() -> None:
    op.execute("DROP TABLE klyrow_delivery_analytics")
    op.execute("DROP TABLE klyrow_delivery_event_inbox")
