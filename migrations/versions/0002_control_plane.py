"""control plane durable state"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_control_plane"
down_revision = "0001_integration_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    u = postgresql.UUID(as_uuid=True)
    j = postgresql.JSONB(astext_type=sa.Text())
    dt = sa.DateTime(timezone=True)
    op.create_table(
        "event_inbox",
        sa.Column("id", u, primary_key=True),
        sa.Column("event_id", sa.String(128), unique=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("payload", j, nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "outbox_event",
        sa.Column("id", u, primary_key=True),
        sa.Column("topic", sa.String(128), nullable=False),
        sa.Column("payload", j, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("next_attempt_at", dt),
        sa.Column("last_error", sa.Text),
        sa.Column("created_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "sync_job",
        sa.Column("id", u, primary_key=True),
        sa.Column("job_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("payload", j, nullable=False),
        sa.Column("last_error", sa.Text),
        sa.Column("next_attempt_at", dt),
    )
    op.create_table(
        "webhook_delivery",
        sa.Column("id", u, primary_key=True),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column("event_id", u, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("last_error", sa.Text),
        sa.Column("next_attempt_at", dt),
    )
    op.create_table(
        "audit_event",
        sa.Column("id", u, primary_key=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("redacted_payload", j, nullable=False),
        sa.Column("created_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "policy_decision",
        sa.Column("id", u, primary_key=True),
        sa.Column("policy", sa.String(128), nullable=False),
        sa.Column("allowed", sa.Boolean, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("context", j, nullable=False),
        sa.Column("created_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "reconciliation_checkpoint",
        sa.Column("id", u, primary_key=True),
        sa.Column("source", sa.String(64), unique=True, nullable=False),
        sa.Column("cursor", sa.String(256)),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("updated_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "transfer_policy_decision",
        sa.Column("id", u, primary_key=True),
        sa.Column("transfer_id", sa.String(128), nullable=False),
        sa.Column("allowed", sa.Boolean, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("created_at", dt, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "system_health_snapshot",
        sa.Column("id", u, primary_key=True),
        sa.Column("component", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("details", j, nullable=False),
        sa.Column("checked_at", dt, server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "system_health_snapshot",
        "transfer_policy_decision",
        "reconciliation_checkpoint",
        "policy_decision",
        "audit_event",
        "webhook_delivery",
        "sync_job",
        "outbox_event",
        "event_inbox",
    ):
        op.drop_table(table)
