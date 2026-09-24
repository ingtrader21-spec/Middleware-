"""Add durable governed TTS job state.

Revision ID: 0033_tts_job_runtime
Revises: 0032_ai_worker_queue_runtime
"""

from alembic import op

revision = "0033_tts_job_runtime"
down_revision = "0032_ai_worker_queue_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE tts_generation_jobs (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
      requested_by text NOT NULL, project_key text NOT NULL, voice_alias text NOT NULL,
      model_alias text NOT NULL, output_profile text NOT NULL,
      idempotency_key text NOT NULL, correlation_id text NOT NULL,
      request_sha256 char(64) NOT NULL, character_count integer NOT NULL,
      state text NOT NULL DEFAULT 'queued', attempt_count integer NOT NULL DEFAULT 0,
      max_attempts integer NOT NULL DEFAULT 2, fencing_token bigint NOT NULL DEFAULT 0,
      lease_owner text, lease_expires_at timestamptz, provider_request_started_at timestamptz,
      first_chunk_at timestamptz, completed_at timestamptz, cancellation_at timestamptz,
      chunk_count bigint NOT NULL DEFAULT 0, audio_bytes bigint NOT NULL DEFAULT 0,
      failure_class text, created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(organization_id,workspace_id,project_key,requested_by,idempotency_key),
      CONSTRAINT ck_tts_job_state CHECK (state IN ('queued','claimed','provider_starting',
        'streaming','completed','failed','cancelled','ambiguous_provider_outcome')),
      CONSTRAINT ck_tts_attempts CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 2),
      CONSTRAINT ck_tts_request_hash CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
      CONSTRAINT ck_tts_counts CHECK (character_count BETWEEN 1 AND 1000 AND chunk_count >= 0 AND audio_bytes >= 0)
    )""")
    op.execute(
        "CREATE INDEX ix_tts_job_claim ON tts_generation_jobs(state,lease_expires_at,created_at)"
    )
    op.execute(
        "CREATE INDEX ix_tts_job_tenant_state ON tts_generation_jobs(organization_id,workspace_id,state,created_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE tts_generation_jobs")
