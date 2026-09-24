"""Add durable worker dead-letter evidence and recovery controls.

Revision ID: 0032_ai_worker_queue_runtime
Revises: 0031_ai_orchestration_v1
"""

import hashlib

from alembic import op
from sqlalchemy import text

revision = "0032_ai_worker_queue_runtime"
down_revision = "0031_ai_orchestration_v1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """ALTER TABLE ai_job_dead_letters
        ADD COLUMN final_error_code text,
        ADD COLUMN max_attempts integer,
        ADD COLUMN safe_error_details jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN failed_at timestamptz,
        ADD COLUMN task_id uuid,
        ADD COLUMN tenant_id uuid,
        ADD COLUMN correlation_id text,
        ADD COLUMN evidence_hash char(64),
        ADD COLUMN manual_retry_requires_new_approval boolean NOT NULL DEFAULT true"""
    )
    connection = op.get_bind()
    rows = connection.execute(
        text("""
        SELECT d.job_id,d.safe_error_code,d.attempt_count,d.created_at,
          d.organization_id,j.max_attempts,j.correlation_id
        FROM ai_job_dead_letters d
        JOIN ai_generation_jobs j ON j.id=d.job_id
    """)
    ).mappings()
    for row in rows:
        evidence_hash = hashlib.sha256(
            f"{row['job_id']}:{row['safe_error_code']}:{row['attempt_count']}".encode()
        ).hexdigest()
        connection.execute(
            text("""
            UPDATE ai_job_dead_letters SET final_error_code=:error,
              max_attempts=:max_attempts,failed_at=:failed_at,task_id=:job,
              tenant_id=:tenant,correlation_id=:correlation,evidence_hash=:evidence
            WHERE job_id=:job
        """),
            {
                "job": row["job_id"],
                "error": row["safe_error_code"],
                "max_attempts": min(row["max_attempts"], row["attempt_count"]),
                "failed_at": row["created_at"],
                "tenant": row["organization_id"],
                "correlation": row["correlation_id"] or "legacy-dead-letter",
                "evidence": evidence_hash,
            },
        )
    for statement in (
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN final_error_code SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN max_attempts SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN failed_at SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN task_id SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN tenant_id SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN correlation_id SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ALTER COLUMN evidence_hash SET NOT NULL",
        "ALTER TABLE ai_job_dead_letters ADD CONSTRAINT ck_ai_dead_letter_attempts CHECK (attempt_count > 0 AND max_attempts > 0)",
        "ALTER TABLE ai_job_dead_letters ADD CONSTRAINT ck_ai_dead_letter_evidence CHECK (evidence_hash ~ '^[0-9a-f]{64}$')",
        "CREATE INDEX ix_ai_dead_letter_tenant_failed ON ai_job_dead_letters(tenant_id,workspace_id,failed_at DESC)",
    ):
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP INDEX ix_ai_dead_letter_tenant_failed",
        "ALTER TABLE ai_job_dead_letters DROP CONSTRAINT ck_ai_dead_letter_evidence",
        "ALTER TABLE ai_job_dead_letters DROP CONSTRAINT ck_ai_dead_letter_attempts",
        """ALTER TABLE ai_job_dead_letters
        DROP COLUMN manual_retry_requires_new_approval,
        DROP COLUMN evidence_hash,
        DROP COLUMN correlation_id,
        DROP COLUMN tenant_id,
        DROP COLUMN task_id,
        DROP COLUMN failed_at,
        DROP COLUMN safe_error_details,
        DROP COLUMN max_attempts,
        DROP COLUMN final_error_code""",
    ):
        op.execute(statement)
