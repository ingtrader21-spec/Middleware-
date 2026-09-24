"""Persist the evidence-backed fine lifecycle state and ordering cursor."""

from alembic import op
import sqlalchemy as sa

revision = "0065_lifecycle_outcome_state"
down_revision = "0064_lifecycle_fine_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column("fine_state", sa.String(32), nullable=True),
    )
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column("fine_state_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column(
            "last_event_sequence",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column("hangup_leg", sa.String(16), nullable=True),
    )
    op.execute(
        "UPDATE telephony_call_lifecycle "
        "SET fine_state='requested' WHERE fine_state IS NULL"
    )
    op.execute(
        "UPDATE telephony_call_lifecycle "
        "SET fine_state_at=COALESCE(created_at, CURRENT_TIMESTAMP) "
        "WHERE fine_state_at IS NULL"
    )
    op.alter_column(
        "telephony_call_lifecycle",
        "fine_state",
        nullable=False,
        server_default=sa.text("'requested'"),
    )
    op.create_check_constraint(
        "ck_telephony_call_fine_state",
        "telephony_call_lifecycle",
        "fine_state IN "
        "('requested','accepted','queued','dialing','ringing','answered',"
        "'connected','completed','failed','busy','no_answer','canceled',"
        "'rejected')",
    )
    op.create_check_constraint(
        "ck_telephony_call_hangup_leg",
        "telephony_call_lifecycle",
        "hangup_leg IS NULL OR hangup_leg IN ('agent_leg','peer_leg')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_telephony_call_hangup_leg",
        "telephony_call_lifecycle",
        type_="check",
    )
    op.drop_constraint(
        "ck_telephony_call_fine_state",
        "telephony_call_lifecycle",
        type_="check",
    )
    op.drop_column("telephony_call_lifecycle", "hangup_leg")
    op.drop_column("telephony_call_lifecycle", "last_event_sequence")
    op.drop_column("telephony_call_lifecycle", "fine_state_at")
    op.drop_column("telephony_call_lifecycle", "fine_state")
