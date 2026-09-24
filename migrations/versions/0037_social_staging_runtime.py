"""Durable social staging runtime and idempotency.

Revision ID: 0037_social_staging
Revises: 0036_social_publishing
"""

from alembic import op

revision = "0037_social_staging"
down_revision = "0036_social_publishing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = (
        """CREATE TABLE social_idempotency_records (
        tenant_id uuid NOT NULL, action text NOT NULL, subject_id uuid NOT NULL,
        key_hash char(64) NOT NULL, request_hash char(64) NOT NULL,
        social_post_id uuid NOT NULL, job_id uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id,action,subject_id,key_hash))""",
        """ALTER TABLE social_publish_jobs
        ADD COLUMN lease_owner text,
        ADD COLUMN lease_expires_at timestamptz,
        ADD COLUMN fencing_token bigint NOT NULL DEFAULT 0,
        ADD COLUMN provider_request_id text,
        ADD COLUMN result_certainty text NOT NULL DEFAULT 'NOT_SENT',
        ADD CONSTRAINT ck_social_job_certainty CHECK
          (result_certainty IN ('NOT_SENT','FAILED_BEFORE_SEND','CONFIRMED','UNKNOWN_AFTER_SEND'))""",
        """ALTER TABLE social_webhook_events
        ADD COLUMN normalized_event_type text,
        ADD COLUMN subject_id uuid,
        ADD COLUMN tenant_id uuid,
        ADD COLUMN rejection_code text""",
        "CREATE INDEX ix_social_jobs_lease ON social_publish_jobs(state,lease_expires_at,next_attempt_at)",
        "CREATE INDEX ix_social_webhook_tenant_received ON social_webhook_events(tenant_id,received_at DESC)",
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP INDEX ix_social_webhook_tenant_received",
        "DROP INDEX ix_social_jobs_lease",
        """ALTER TABLE social_webhook_events
        DROP COLUMN rejection_code, DROP COLUMN tenant_id,
        DROP COLUMN subject_id, DROP COLUMN normalized_event_type""",
        """ALTER TABLE social_publish_jobs
        DROP CONSTRAINT ck_social_job_certainty,
        DROP COLUMN result_certainty, DROP COLUMN provider_request_id,
        DROP COLUMN fencing_token, DROP COLUMN lease_expires_at, DROP COLUMN lease_owner""",
        "DROP TABLE social_idempotency_records",
    ):
        op.execute(statement)
