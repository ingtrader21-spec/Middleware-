"""Add fail-closed identity and lead orchestration records.

Revision ID: 0008_orchestration
Revises: 0006_lead_reconciliation, 0007_fast_ack_outbox
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_orchestration"
down_revision = ("0006_lead_reconciliation", "0007_fast_ack_outbox")
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "orchestration_request",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("request_uid", sa.String(128), nullable=False, unique=True),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("business_unit", sa.String(16), nullable=False),
        sa.Column("subject_reference", sa.String(128), nullable=False),
        sa.Column("department_reference", sa.String(128), nullable=False),
        sa.Column("team_reference", sa.String(128), nullable=False),
        sa.Column("supervisor_reference", sa.String(128), nullable=False),
        sa.Column("campaign_references", postgresql.JSONB(), nullable=False),
        sa.Column("requested_resources", postgresql.JSONB(), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="disabled"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_orchestration_request_business_unit",
        "orchestration_request",
        ["business_unit"],
    )
    op.create_index(
        "ix_orchestration_request_correlation_id",
        "orchestration_request",
        ["correlation_id"],
    )
    op.create_table(
        "credential_grant",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "orchestration_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("orchestration_request.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("credential_type", sa.String(32), nullable=False),
        sa.Column("vault_reference", sa.String(255), nullable=False),
        sa.Column("secret_fingerprint", sa.String(128), nullable=False),
        sa.Column("retrieval_token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "lead_sync_request",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_reference", sa.String(128), nullable=False),
        sa.Column("business_unit", sa.String(16), nullable=False),
        sa.Column("campaign_reference", sa.String(128), nullable=False),
        sa.Column("list_reference", sa.String(128), nullable=False),
        sa.Column("canonical_payload", postgresql.JSONB(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="disabled"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_lead_sync_request_business_unit", "lead_sync_request", ["business_unit"]
    )
    op.create_index(
        "ix_lead_sync_request_correlation_id", "lead_sync_request", ["correlation_id"]
    )


def downgrade():
    op.drop_table("lead_sync_request")
    op.drop_table("credential_grant")
    op.drop_table("orchestration_request")
