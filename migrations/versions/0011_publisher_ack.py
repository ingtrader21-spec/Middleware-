"""durable publisher authentication replay and acknowledgements"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011_publisher_ack"
down_revision = "0010_vicidial_registry_guards"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "publisher_nonce",
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("signed_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_id", "nonce"),
    )
    op.create_table(
        "publisher_acknowledgement",
        sa.Column(
            "acknowledgement_id", postgresql.UUID(as_uuid=True), primary_key=True
        ),
        sa.Column("event_id", sa.String(128), nullable=False, unique=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("duplicate", sa.Boolean(), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("acknowledgement", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_table("publisher_acknowledgement")
    op.drop_table("publisher_nonce")
