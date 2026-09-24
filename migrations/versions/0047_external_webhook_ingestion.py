"""Add bounded external webhook receipts.

Revision ID: 0047_external_webhooks
Revises: 0046_breero_complete_envelope
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0047_external_webhooks"
down_revision = "0046_breero_complete_envelope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_webhook_receipt",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("external_event_id", sa.String(128), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("signature_valid", sa.Boolean(), nullable=False),
        sa.Column("raw_event_type", sa.String(128), nullable=False),
        sa.Column("canonical_event_type", sa.String(128), nullable=False),
        sa.Column("minimized_payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("last_error", sa.String(128)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("category", "provider", "external_event_id", name="uq_external_webhook_event"),
        sa.UniqueConstraint("category", "provider", "nonce_hash", name="uq_external_webhook_nonce"),
    )
    op.create_index("ix_external_webhook_claim", "external_webhook_receipt", ["status", "next_attempt_at", "received_at"])
    op.create_index("ix_external_webhook_correlation", "external_webhook_receipt", ["correlation_id"])


def downgrade() -> None:
    op.drop_table("external_webhook_receipt")
