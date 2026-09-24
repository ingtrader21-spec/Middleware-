"""durable outbox leases, dead letters, replay, and metrics

Revision ID: 0005_durable_outbox
Revises: 0004_automation_reporting
"""

from alembic import op

revision = "0005_durable_outbox"
down_revision = "0004_automation_reporting"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE outbox_event ADD COLUMN IF NOT EXISTS correlation_id varchar(128)"
    )
    op.execute(
        "ALTER TABLE outbox_event ADD COLUMN IF NOT EXISTS locked_at timestamptz"
    )
    op.execute(
        "ALTER TABLE outbox_event ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz"
    )
    op.execute(
        "ALTER TABLE outbox_event ADD COLUMN IF NOT EXISTS replay_count integer NOT NULL DEFAULT 0"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_outbox_event_claim ON outbox_event (status, next_attempt_at, created_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_outbox_event_correlation_id ON outbox_event (correlation_id)"
    )
    op.execute(
        "ALTER TABLE outbox_event ADD CONSTRAINT ck_outbox_attempts_nonnegative CHECK (attempts >= 0)"
    )
    op.execute(
        "ALTER TABLE outbox_event ADD CONSTRAINT ck_outbox_replay_count_nonnegative CHECK (replay_count >= 0)"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_outbox_replay_count_nonnegative", "outbox_event", type_="check"
    )
    op.drop_constraint("ck_outbox_attempts_nonnegative", "outbox_event", type_="check")
    op.drop_index("ix_outbox_event_correlation_id", table_name="outbox_event")
    op.drop_index("ix_outbox_event_claim", table_name="outbox_event")
    op.drop_column("outbox_event", "replay_count")
    op.drop_column("outbox_event", "dead_lettered_at")
    op.drop_column("outbox_event", "locked_at")
    op.drop_column("outbox_event", "correlation_id")
