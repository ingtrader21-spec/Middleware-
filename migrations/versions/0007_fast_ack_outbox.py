"""fast ACK schema and authoritative integration delivery leases

Revision ID: 0007_fast_ack_outbox
Revises: 0005_durable_outbox
"""

from alembic import op

revision = "0007_fast_ack_outbox"
down_revision = "0005_durable_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE integration_event ADD COLUMN IF NOT EXISTS schema_version varchar(16) NOT NULL DEFAULT '1.0'"
    )
    op.execute(
        "ALTER TABLE integration_event ADD COLUMN IF NOT EXISTS original_event_id varchar(128)"
    )
    op.execute(
        "ALTER TABLE integration_event ADD COLUMN IF NOT EXISTS entity_key varchar(256)"
    )
    op.execute(
        "UPDATE integration_event SET original_event_id='legacy-' || id WHERE original_event_id IS NULL"
    )
    op.execute(
        "ALTER TABLE integration_event ALTER COLUMN original_event_id SET NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_event_original_event_id ON integration_event(original_event_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_integration_event_entity_order ON integration_event(entity_key, id)"
    )
    op.execute(
        "ALTER TABLE idempotency_record ADD COLUMN IF NOT EXISTS expires_at timestamptz"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD COLUMN IF NOT EXISTS lease_owner varchar(128)"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD COLUMN IF NOT EXISTS available_at timestamptz"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD COLUMN IF NOT EXISTS max_attempts integer NOT NULL DEFAULT 5"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD COLUMN IF NOT EXISTS result_json jsonb"
    )
    # Legacy queued rows are deliberately fail-closed during the migration.
    op.execute(
        "UPDATE integration_delivery SET status='disabled' WHERE status='queued'"
    )
    op.execute(
        "UPDATE integration_delivery SET status='retry_wait' WHERE status='retry'"
    )
    op.execute(
        "UPDATE integration_delivery SET status='leased' WHERE status='processing'"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_integration_delivery_claim ON integration_delivery(target,status,available_at,lease_expires_at,event_id)"
    )
    op.execute(
        "ALTER TABLE integration_delivery ADD CONSTRAINT ck_integration_delivery_status CHECK (status IN ('disabled','pending','leased','delivered','retry_wait','dead_letter','canceled'))"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_integration_delivery_status", "integration_delivery", type_="check"
    )
    op.drop_index("ix_integration_delivery_claim", table_name="integration_delivery")
    for column in (
        "result_json",
        "max_attempts",
        "available_at",
        "lease_expires_at",
        "lease_owner",
    ):
        op.drop_column("integration_delivery", column)
    op.drop_column("idempotency_record", "expires_at")
    op.drop_index("ix_integration_event_entity_order", table_name="integration_event")
    op.drop_index(
        "uq_integration_event_original_event_id", table_name="integration_event"
    )
    for column in ("entity_key", "original_event_id", "schema_version"):
        op.drop_column("integration_event", column)
