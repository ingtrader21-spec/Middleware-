"""Add the authoritative scraper receipt and processing inbox.

Revision ID: 0043_scraper_durable_inbox
Revises: 0042_merge_gateway_trust
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0043_scraper_durable_inbox"
down_revision = "0042_merge_gateway_trust"
branch_labels = None
depends_on = None

STATES = (
    "received",
    "eligible",
    "rejected",
    "queued",
    "processing",
    "retry_wait",
    "delivered",
    "dead_letter",
)


def upgrade() -> None:
    op.create_table(
        "sales_scraper_inbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("source_identity", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(128), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("rejection_code", sa.String(64)),
        sa.Column("odoo_result_reference", sa.String(128)),
        sa.Column("n8n_result_reference", sa.String(128)),
        sa.Column(
            "received_at",
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
        sa.CheckConstraint("attempts >= 0", name="ck_sales_scraper_inbox_attempts"),
        sa.CheckConstraint(
            "status IN (" + ",".join(f"'{state}'" for state in STATES) + ")",
            name="ck_sales_scraper_inbox_status",
        ),
        sa.UniqueConstraint(
            "source_identity", "event_id", name="uq_sales_scraper_inbox_event"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key_hash",
            name="uq_sales_scraper_inbox_idempotency",
        ),
    )
    op.create_index(
        "ix_sales_scraper_inbox_work",
        "sales_scraper_inbox",
        ["status", "next_attempt_at", "received_at"],
    )
    op.create_index(
        "ix_sales_scraper_inbox_trace",
        "sales_scraper_inbox",
        ["tenant_id", "correlation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_sales_scraper_inbox_trace", table_name="sales_scraper_inbox")
    op.drop_index("ix_sales_scraper_inbox_work", table_name="sales_scraper_inbox")
    op.drop_table("sales_scraper_inbox")
