"""MCR durable decision ledger and idempotent readback.

Revision ID: 0070_campaign_recycling_decision_ledger
Revises: 0069_campaign_recycling_delivery_events
"""

from alembic import op

revision = "0070_campaign_recycling_decision_ledger"
down_revision = "0069_campaign_recycling_delivery_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE mcr_decisions (
      record_id uuid NOT NULL,
      tenant_id text NOT NULL,
      decision_id uuid NOT NULL,
      lead_id text NOT NULL,
      idempotency_key text NOT NULL,
      request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
      response_hash char(64) NOT NULL CHECK (response_hash ~ '^[0-9a-f]{64}$'),
      decision_hash char(64) NOT NULL CHECK (decision_hash ~ '^[0-9a-f]{64}$'),
      policy_version text NOT NULL,
      lifecycle_state text NOT NULL,
      mode text NOT NULL CHECK (mode IN ('plan','read','execute')),
      eligible boolean NOT NULL,
      next_eligible_at timestamptz,
      correlation_id text NOT NULL,
      evaluated_at timestamptz NOT NULL,
      decision_json jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_id, record_id),
      UNIQUE (tenant_id, idempotency_key)
    )""")
    op.execute(
        """CREATE INDEX ix_mcr_decisions_lead_latest
        ON mcr_decisions(tenant_id, lead_id, evaluated_at DESC, created_at DESC)"""
    )
    op.execute(
        """CREATE INDEX ix_mcr_decisions_identity
        ON mcr_decisions(tenant_id, decision_id)"""
    )
    op.execute(
        """CREATE TRIGGER mcr_decisions_append_only
        BEFORE UPDATE OR DELETE ON mcr_decisions
        FOR EACH ROW EXECUTE FUNCTION mcr_reject_append_only_mutation()"""
    )


def downgrade() -> None:
    op.execute("""DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM mcr_decisions) THEN
        RAISE EXCEPTION 'mcr_decisions holds durable decision evidence; downgrade refused';
      END IF;
    END $$""")
    op.execute("DROP TRIGGER IF EXISTS mcr_decisions_append_only ON mcr_decisions")
    op.execute("DROP TABLE mcr_decisions")
