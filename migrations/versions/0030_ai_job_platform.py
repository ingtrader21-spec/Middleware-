"""Durable tenant-isolated AI job platform.

Revision ID: 0030_ai_job_platform
Revises: 0029_merge_lead_recording_heads
"""

from alembic import op

revision = "0030_ai_job_platform"
down_revision = "0029_merge_lead_recording_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = ("""
    CREATE TABLE ai_service_nonces (
      service_id text NOT NULL, nonce_digest char(64) NOT NULL,
      received_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
      correlation_id text,
      PRIMARY KEY(service_id, nonce_digest),
      CONSTRAINT ck_ai_nonce_digest CHECK (nonce_digest ~ '^[0-9a-f]{64}$')
    )
    """, "CREATE INDEX ix_ai_service_nonce_expiry ON ai_service_nonces(expires_at)", """
    CREATE TABLE ai_conversations (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
      created_by text NOT NULL, title text NOT NULL, status text NOT NULL DEFAULT 'active',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_ai_conversation_status CHECK (status IN ('active','archived'))
    )
    """, "CREATE INDEX ix_ai_conversation_tenant ON ai_conversations(organization_id, workspace_id, created_at DESC)", """
    CREATE TABLE ai_messages (
      id uuid PRIMARY KEY, conversation_id uuid NOT NULL REFERENCES ai_conversations(id) ON DELETE RESTRICT,
      organization_id uuid NOT NULL, workspace_id uuid NOT NULL, role text NOT NULL,
      content text NOT NULL, content_sha256 char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_ai_message_role CHECK (role IN ('user','assistant','system'))
    )
    """, "CREATE INDEX ix_ai_message_conversation ON ai_messages(organization_id, workspace_id, conversation_id, created_at)", """
    CREATE TABLE ai_generation_jobs (
      id uuid PRIMARY KEY, conversation_id uuid NOT NULL REFERENCES ai_conversations(id) ON DELETE RESTRICT,
      request_message_id uuid NOT NULL REFERENCES ai_messages(id) ON DELETE RESTRICT,
      organization_id uuid NOT NULL, workspace_id uuid NOT NULL, requested_by text NOT NULL,
      task_type text NOT NULL, project_key text, state text NOT NULL DEFAULT 'queued',
      idempotency_key text NOT NULL, request_sha256 char(64) NOT NULL,
      attempt_count integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 5,
      fencing_token bigint NOT NULL DEFAULT 0, lease_owner text, lease_expires_at timestamptz,
      next_attempt_at timestamptz NOT NULL DEFAULT now(), cancel_requested_at timestamptz,
      completed_at timestamptz, failure_code text, output_bytes bigint NOT NULL DEFAULT 0,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(organization_id, workspace_id, idempotency_key),
      CONSTRAINT ck_ai_job_state CHECK (state IN ('queued','leased','retry_wait','completed','failed','cancelled','dead_letter')),
      CONSTRAINT ck_ai_job_attempts CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10)
    )
    """, "CREATE INDEX ix_ai_job_claim ON ai_generation_jobs(state, next_attempt_at, lease_expires_at, created_at)", """
    CREATE TABLE ai_job_chunks (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
      organization_id uuid NOT NULL, workspace_id uuid NOT NULL, sequence bigint NOT NULL,
      fencing_token bigint NOT NULL, content text NOT NULL, content_sha256 char(64) NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(job_id, sequence)
    )
    """, """
    CREATE TABLE ai_job_attempts (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
      attempt_number integer NOT NULL, fencing_token bigint NOT NULL, worker_id text NOT NULL,
      state text NOT NULL, safe_error_code text, started_at timestamptz NOT NULL DEFAULT now(),
      finished_at timestamptz, UNIQUE(job_id, attempt_number)
    )
    """, """
    CREATE TABLE ai_worker_heartbeats (
      worker_id text PRIMARY KEY, service_id text NOT NULL, certificate_serial text NOT NULL,
      spiffe_id text NOT NULL, last_seen_at timestamptz NOT NULL DEFAULT now(), current_job_id uuid
    )
    """, """
    CREATE TABLE ai_audit_events (
      id uuid PRIMARY KEY, organization_id uuid, workspace_id uuid, job_id uuid,
      actor_fingerprint char(64) NOT NULL, event_type text NOT NULL, correlation_id text NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}'::jsonb, occurred_at timestamptz NOT NULL DEFAULT now()
    )
    """, """
    CREATE FUNCTION deny_ai_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'append-only AI audit'; END $$;
    """, """CREATE TRIGGER ai_audit_append_only BEFORE UPDATE OR DELETE ON ai_audit_events
      FOR EACH ROW EXECUTE FUNCTION deny_ai_audit_mutation();
    """)
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP TRIGGER IF EXISTS ai_audit_append_only ON ai_audit_events",
        "DROP FUNCTION IF EXISTS deny_ai_audit_mutation()",
        "DROP TABLE ai_audit_events", "DROP TABLE ai_worker_heartbeats",
        "DROP TABLE ai_job_attempts", "DROP TABLE ai_job_chunks",
        "DROP TABLE ai_generation_jobs", "DROP TABLE ai_messages",
        "DROP TABLE ai_conversations", "DROP TABLE ai_service_nonces",
    ):
        op.execute(statement)
