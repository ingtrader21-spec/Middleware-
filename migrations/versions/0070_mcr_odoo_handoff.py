"""MCR Odoo handoff durable no-effect ledger.

Revision ID: 0070_mcr_odoo_handoff
Revises: 0069_campaign_recycling_delivery_events
"""
from alembic import op

revision = "0070_mcr_odoo_handoff"
down_revision = "0069_campaign_recycling_delivery_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE mcr_odoo_handoffs (
      tenant_id text NOT NULL,
      command_id uuid NOT NULL,
      lead_id text NOT NULL,
      campaign_id text NOT NULL CHECK (campaign_id ~ '^(klyrow|whatsapp):'),
      campaign_version integer NOT NULL CHECK (campaign_version >= 1),
      lifecycle_version integer NOT NULL CHECK (lifecycle_version >= 1),
      policy_version text NOT NULL,
      handoff text NOT NULL CHECK (handoff IN ('accepted','engaged','conversion')),
      idempotency_key text NOT NULL CHECK (idempotency_key ~ '^mcrodoo1:[a-f0-9]{64}$'),
      correlation_id text NOT NULL,
      causation_id text NOT NULL,
      payload_hash char(64) NOT NULL CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
      status text NOT NULL CHECK (status IN ('accepted','applied','not_found','unknown','rejected')),
      odoo_record_id bigint,
      observed_lifecycle_version integer,
      observed_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL,
      PRIMARY KEY (tenant_id, command_id),
      UNIQUE (tenant_id, idempotency_key),
      UNIQUE (tenant_id, lead_id, campaign_id, campaign_version,
              lifecycle_version, policy_version, handoff),
      CHECK (
        (status='applied' AND odoo_record_id IS NOT NULL AND observed_lifecycle_version IS NOT NULL)
        OR
        (status<>'applied' AND odoo_record_id IS NULL AND observed_lifecycle_version IS NULL)
      )
    )
    """)
    op.execute("""
    CREATE TABLE mcr_odoo_handoff_reconciliations (
      reconciliation_id uuid PRIMARY KEY,
      tenant_id text NOT NULL,
      command_id uuid NOT NULL,
      idempotency_key text NOT NULL,
      correlation_id text NOT NULL,
      causation_id text NOT NULL,
      requested_at timestamptz NOT NULL,
      UNIQUE (tenant_id, idempotency_key),
      FOREIGN KEY (tenant_id, command_id)
        REFERENCES mcr_odoo_handoffs(tenant_id, command_id)
    )
    """)
    op.execute(
        "CREATE INDEX ix_mcr_odoo_handoff_status "
        "ON mcr_odoo_handoffs(tenant_id,status,updated_at)"
    )


def downgrade() -> None:
    op.execute("""DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM mcr_odoo_handoffs)
         OR EXISTS (SELECT 1 FROM mcr_odoo_handoff_reconciliations) THEN
        RAISE EXCEPTION 'MCR Odoo handoff evidence exists; downgrade refused';
      END IF;
    END $$""")
    op.execute("DROP TABLE mcr_odoo_handoff_reconciliations")
    op.execute("DROP TABLE mcr_odoo_handoffs")
