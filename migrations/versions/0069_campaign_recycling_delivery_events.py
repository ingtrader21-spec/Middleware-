"""MCR normalized delivery-event ledger and replay authority.

Revision ID: 0069_campaign_recycling_delivery_events
Revises: 0068_campaign_recycling_core

Stores normalized cross-channel delivery/engagement events owned by Middleware.
The source/event identity and optional raw-inbox origin are unique. Replays with
the same digest can be re-projected when a prior projection is partial; payload
identity conflicts fail closed. No provider capability or route is enabled.
"""

from alembic import op

revision = "0069_campaign_recycling_delivery_events"
down_revision = "0068_campaign_recycling_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE mcr_delivery_events (
      id bigserial PRIMARY KEY,
      tenant_id text NOT NULL,
      source text NOT NULL,
      event_id text NOT NULL,
      event_type text NOT NULL,
      lead_id text NOT NULL,
      channel text NOT NULL,
      campaign_id text,
      campaign_version integer,
      exposure_idempotency_key text,
      address_ref text,
      provider text,
      message_id text,
      provider_message_id text,
      correlation_id text NOT NULL,
      causation_id text,
      payload_hash char(64) NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
      occurred_at timestamptz NOT NULL,
      received_at timestamptz NOT NULL,
      origin_inbox text,
      origin_event_id text,
      normalized_event jsonb NOT NULL,
      projection_state text NOT NULL DEFAULT 'pending'
        CHECK (projection_state IN ('pending','partial','applied')),
      projection_note text,
      projected_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, source, event_id),
      CHECK (
        (origin_inbox IS NULL AND origin_event_id IS NULL)
        OR (origin_inbox IS NOT NULL AND origin_event_id IS NOT NULL)
      )
    )""")
    op.execute(
        """CREATE UNIQUE INDEX uq_mcr_delivery_event_origin
        ON mcr_delivery_events(tenant_id, origin_inbox, origin_event_id)
        WHERE origin_inbox IS NOT NULL"""
    )
    op.execute(
        """CREATE INDEX ix_mcr_delivery_events_lead_time
        ON mcr_delivery_events(tenant_id, lead_id, occurred_at, id)"""
    )
    op.execute(
        """CREATE INDEX ix_mcr_delivery_events_projection
        ON mcr_delivery_events(projection_state, received_at)
        WHERE projection_state <> 'applied'"""
    )
    op.execute(
        """CREATE TRIGGER mcr_delivery_events_append_only
        BEFORE DELETE ON mcr_delivery_events
        FOR EACH ROW EXECUTE FUNCTION mcr_reject_append_only_mutation()"""
    )


def downgrade() -> None:
    op.execute("""DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM mcr_delivery_events) THEN
        RAISE EXCEPTION 'mcr_delivery_events holds normalized delivery evidence; downgrade refused';
      END IF;
    END $$""")
    op.execute(
        "DROP TRIGGER IF EXISTS mcr_delivery_events_append_only ON mcr_delivery_events"
    )
    op.execute("DROP TABLE mcr_delivery_events")
