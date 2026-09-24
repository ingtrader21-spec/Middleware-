"""Add fine-grained event tracking to telephony_call_lifecycle.

telephony_call_lifecycle only tracks a coarse STARTED/CONNECTED/ENDED
state (see 0014_telephony_call_lifecycle.py), which is much coarser than
the VICIdial-sourced event taxonomy already flowing through the NATS
projection pipeline (call.dialing/ringing/answered/connected/held/
transferring/hangup/completed/failed/busy/no_answer/rejected/canceled/
timeout -- see
app/vicidial_odoo_projection_lifecycle_sync.py and Odoo's matching
CALL_EVENTS taxonomy in call_event_projection.py). This is purely
additive: the existing coarse columns and their consumers are untouched.
"""

from alembic import op
import sqlalchemy as sa

revision = "0064_lifecycle_fine_state"
down_revision = "0063_telephony_lead_reference"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column("last_event_type", sa.String(64), nullable=True),
    )
    op.add_column(
        "telephony_call_lifecycle",
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("telephony_call_lifecycle", "last_event_at")
    op.drop_column("telephony_call_lifecycle", "last_event_type")
