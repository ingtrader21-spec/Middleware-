"""governed n8n and redis runtime integration

Revision ID: 0034_n8n_redis_runtime
Revises: 0033_tts_job_runtime
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0034_n8n_redis_runtime"
down_revision = "0033_tts_job_runtime"
branch_labels = None
depends_on = None

STATUSES = (
    "PENDING",
    "DISPATCHING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "RETRY",
    "DEAD_LETTER",
    "CANCELLED",
    "TIMED_OUT",
)


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    op.create_table(
        "n8n_workflow_registry",
        sa.Column("registry_id", uuid, primary_key=True),
        sa.Column("workflow_code", sa.String(128), nullable=False),
        sa.Column("workflow_version", sa.String(32), nullable=False),
        sa.Column("n8n_workflow_id", sa.String(128), nullable=False),
        sa.Column("event_types", jsonb, nullable=False),
        sa.Column("tenant_scope", jsonb, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "timeout_seconds", sa.Integer(), nullable=False, server_default="600"
        ),
        sa.Column("retry_policy", jsonb, nullable=False),
        sa.Column("result_contract", sa.String(64), nullable=False),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("webhook_path", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "workflow_code", "workflow_version", name="uq_n8n_registry_code_version"
        ),
        sa.UniqueConstraint("n8n_workflow_id", name="uq_n8n_registry_workflow_id"),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 3600", name="ck_n8n_registry_timeout"
        ),
        sa.CheckConstraint(
            "webhook_path ~ '^/[A-Za-z0-9/_-]+$'", name="ck_n8n_registry_webhook_path"
        ),
    )
    op.create_table(
        "n8n_runtime_execution",
        sa.Column("execution_id", uuid, primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=False),
        sa.Column("workflow_code", sa.String(128), nullable=False),
        sa.Column("workflow_version", sa.String(32), nullable=False),
        sa.Column("n8n_execution_id", sa.String(128), unique=True),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("causation_id", sa.String(128), nullable=False),
        sa.Column("trace_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("payload_json", jsonb, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("timeout_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failure_class", sa.String(64)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "tenant_id",
            "event_type",
            "source_event_id",
            "workflow_version",
            "idempotency_key_hash",
            name="uq_n8n_runtime_idempotency",
        ),
        sa.CheckConstraint(
            "status IN (" + ",".join(repr(v) for v in STATUSES) + ")",
            name="ck_n8n_runtime_status",
        ),
        sa.CheckConstraint(
            "attempt_count BETWEEN 0 AND 8", name="ck_n8n_runtime_attempts"
        ),
    )
    op.create_index(
        "ix_n8n_runtime_claim",
        "n8n_runtime_execution",
        ["status", "next_attempt_at", "created_at"],
    )
    op.create_index(
        "ix_n8n_runtime_tenant_correlation",
        "n8n_runtime_execution",
        ["tenant_id", "correlation_id"],
    )
    op.create_table(
        "n8n_runtime_result",
        sa.Column("result_id", uuid, primary_key=True),
        sa.Column(
            "execution_id",
            uuid,
            sa.ForeignKey("n8n_runtime_execution.execution_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("workflow_code", sa.String(128), nullable=False),
        sa.Column("result_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("result_json", jsonb, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "persisted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "execution_id", "result_hash", name="uq_n8n_runtime_result_hash"
        ),
    )
    op.create_table(
        "n8n_runtime_nonce",
        sa.Column("identity", sa.String(128), primary_key=True),
        sa.Column("nonce", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("execution_id", uuid, nullable=False),
        sa.Column("body_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_n8n_runtime_nonce_expiry", "n8n_runtime_nonce", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_n8n_runtime_nonce_expiry", table_name="n8n_runtime_nonce")
    op.drop_table("n8n_runtime_nonce")
    op.drop_table("n8n_runtime_result")
    op.drop_index(
        "ix_n8n_runtime_tenant_correlation", table_name="n8n_runtime_execution"
    )
    op.drop_index("ix_n8n_runtime_claim", table_name="n8n_runtime_execution")
    op.drop_table("n8n_runtime_execution")
    op.drop_table("n8n_workflow_registry")
