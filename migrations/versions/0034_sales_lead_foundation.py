"""Add governed Phase 1 sales lead foundation records.

Revision ID: 0034_sales_lead_foundation
Revises: 0033_tts_job_runtime
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0034_sales_lead_foundation"
down_revision = "0033_tts_job_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sales_lead_candidate",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_public_id", sa.String(64), nullable=False, unique=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(64), nullable=False),
        sa.Column("source_provider", sa.String(64), nullable=False),
        sa.Column("source_request_id", sa.String(128), nullable=False),
        sa.Column("protected_payload_hash", sa.String(64), nullable=False),
        sa.Column("normalized_identity", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "source_provider",
            "source_request_id",
            name="uq_sales_candidate_source_request",
        ),
    )
    op.create_index(
        "ix_sales_candidate_tenant_campaign",
        "sales_lead_candidate",
        ["tenant_id", "campaign_id"],
    )
    op.create_table(
        "sales_identity_resolution",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_public_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("company_score", sa.Integer(), nullable=False),
        sa.Column("contact_score", sa.Integer(), nullable=False),
        sa.Column("odoo_company_public_id", sa.String(128)),
        sa.Column("odoo_lead_public_id", sa.String(128)),
        sa.Column("reason_codes", postgresql.JSONB(), nullable=False),
        sa.Column("gate_results", postgresql.JSONB(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "company_score BETWEEN 0 AND 100", name="ck_sales_company_score"
        ),
        sa.CheckConstraint(
            "contact_score BETWEEN 0 AND 100", name="ck_sales_contact_score"
        ),
        sa.UniqueConstraint(
            "tenant_id", "candidate_public_id", name="uq_sales_resolution_candidate"
        ),
    )
    op.create_table(
        "sales_duplicate_review",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("review_public_id", sa.String(64), nullable=False, unique=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(128), nullable=False),
        sa.Column("candidate_public_id", sa.String(64), nullable=False),
        sa.Column("odoo_company_public_id", sa.String(128)),
        sa.Column("odoo_lead_public_id", sa.String(128)),
        sa.Column("company_score", sa.Integer(), nullable=False),
        sa.Column("contact_score", sa.Integer(), nullable=False),
        sa.Column("match_reason_codes", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_hashes", postgresql.JSONB(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column(
            "review_state", sa.String(32), nullable=False, server_default="PENDING"
        ),
        sa.Column("reviewer_identity", sa.String(128)),
        sa.Column("review_decision_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_sales_review_tenant_state",
        "sales_duplicate_review",
        ["tenant_id", "review_state"],
    )
    op.create_table(
        "sales_verification_job",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_public_id", sa.String(64), nullable=False, unique=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(128)),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("filter_json", postgresql.JSONB(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("total_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warning_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "batch_size BETWEEN 1 AND 100", name="ck_sales_verification_batch"
        ),
    )
    op.create_table(
        "sales_verification_result",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_public_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("candidate_public_id", sa.String(64)),
        sa.Column("classification", sa.String(48), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_sales_verification_result_job",
        "sales_verification_result",
        ["tenant_id", "job_public_id"],
    )
    op.create_table(
        "sales_idempotency",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("result_reference", sa.String(64), nullable=False),
        sa.Column("response_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "operation", "key_hash", name="uq_sales_idempotency_scope"
        ),
    )
    op.create_table(
        "sales_webhook_nonce",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scraper_id", sa.String(128), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("scraper_id", "nonce_hash", name="uq_sales_webhook_nonce"),
    )
    op.create_table(
        "sales_provider_call_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("candidate_public_id", sa.String(64)),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("cost_units", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("safe_error_code", sa.String(64)),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("sales_provider_call_audit")
    op.drop_table("sales_webhook_nonce")
    op.drop_table("sales_idempotency")
    op.drop_index(
        "ix_sales_verification_result_job", table_name="sales_verification_result"
    )
    op.drop_table("sales_verification_result")
    op.drop_table("sales_verification_job")
    op.drop_index("ix_sales_review_tenant_state", table_name="sales_duplicate_review")
    op.drop_table("sales_duplicate_review")
    op.drop_table("sales_identity_resolution")
    op.drop_index(
        "ix_sales_candidate_tenant_campaign", table_name="sales_lead_candidate"
    )
    op.drop_table("sales_lead_candidate")
