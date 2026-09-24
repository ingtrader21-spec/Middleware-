"""Add normalized monotonic telephony call lifecycle persistence."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0014_telephony_call_lifecycle"
down_revision = "0013_telephony_allocation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "telephony_call_lifecycle",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("correlation_id", sa.String(128), nullable=False, unique=True),
        sa.Column("linked_id", sa.String(128)),
        sa.Column("primary_unique_id", sa.String(128), nullable=False),
        sa.Column("lifecycle_state", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("connected_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("disposition", sa.String(64)),
        sa.Column("hangup_cause", sa.String(64)),
        sa.Column("source_extension", sa.String(32), nullable=False),
        sa.Column("destination", sa.String(64), nullable=False),
        sa.Column("dialplan_context", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('STARTED','CONNECTED','ENDED')",
            name="ck_telephony_call_lifecycle_state",
        ),
    )
    op.create_index(
        "ix_telephony_call_lifecycle_linked_id",
        "telephony_call_lifecycle",
        ["linked_id"],
    )
    op.create_table(
        "telephony_call_lifecycle_event",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "call_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("telephony_call_lifecycle.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "integration_event_id",
            sa.BigInteger(),
            sa.ForeignKey("integration_event.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("original_event_id", sa.String(128), nullable=False, unique=True),
        sa.Column("unique_id", sa.String(128), nullable=False),
        sa.Column("channel", sa.String(255), nullable=False),
        sa.Column("incoming_state", sa.String(16), nullable=False),
        sa.Column("previous_state", sa.String(16)),
        sa.Column("resulting_state", sa.String(16), nullable=False),
        sa.Column("transition_applied", sa.Boolean(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade():
    op.drop_table("telephony_call_lifecycle_event")
    op.drop_index(
        "ix_telephony_call_lifecycle_linked_id",
        table_name="telephony_call_lifecycle",
    )
    op.drop_table("telephony_call_lifecycle")
