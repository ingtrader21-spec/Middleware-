"""Durable Klyrow inbound mail delivery ledger.

Revision ID: 0055_klyrow_mail_inbound
Revises: 0054_campaign_actions
"""

from alembic import op

revision = "0055_klyrow_mail_inbound"
down_revision = "0054_campaign_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE klyrow_mail_inbound (
      event_id text PRIMARY KEY,
      idempotency_key text NOT NULL UNIQUE,
      tenant_id text NOT NULL,
      inbound_id text NOT NULL UNIQUE,
      provider_event_id text NOT NULL UNIQUE,
      recipient text NOT NULL,
      destination_kind text NOT NULL CHECK (destination_kind IN ('odoo_helpdesk','odoo_accounting')),
      destination_ref text,
      payload_hash char(64) NOT NULL,
      payload jsonb NOT NULL,
      status text NOT NULL CHECK (status IN ('pending','leased','retry_wait','delivered','dead_letter')),
      attempts integer NOT NULL DEFAULT 0,
      next_attempt_at timestamptz,
      lease_token uuid,
      lease_expires_at timestamptz,
      odoo_record_id bigint,
      last_safe_error text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute(
        "CREATE INDEX ix_klyrow_mail_delivery ON klyrow_mail_inbound(status,next_attempt_at,created_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE klyrow_mail_inbound")
