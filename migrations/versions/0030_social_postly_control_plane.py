"""Durable, fail-closed social/Postly control plane.

Revision ID: 0030_social_postly_control_plane
Revises: 0029_merge_lead_recording_heads
"""

from alembic import op

revision = "0030_social_postly_control_plane"
down_revision = "0029_merge_lead_recording_heads"
branch_labels = None
depends_on = None


TABLES = (
    "social_reconciliation_lease",
    "social_dead_letter",
    "social_delivery_attempt",
    "social_audit_record",
    "social_idempotency_claim",
    "social_publication",
    "social_approval",
    "social_content_version",
    "social_content_job",
)


def upgrade() -> None:
    op.execute("""CREATE TABLE social_content_job (
      id uuid PRIMARY KEY, organization_id text NOT NULL, workspace_id text NOT NULL,
      campaign_id text NOT NULL, content_job_id text NOT NULL, current_version integer NOT NULL,
      integration_ids jsonb NOT NULL,
      preferred_language text NOT NULL, correlation_id varchar(128) NOT NULL, state text NOT NULL,
      scheduled_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, content_job_id), CHECK (current_version >= 1),
      CHECK (preferred_language IN ('en','es','fr','ht'))
    )""")
    op.execute("""CREATE TABLE social_content_version (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES social_content_job(id) ON DELETE RESTRICT,
      version integer NOT NULL, proposal jsonb NOT NULL, proposal_sha256 char(64) NOT NULL,
      workflow_execution_id text, created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (job_id, version), UNIQUE (job_id, proposal_sha256), CHECK (version >= 1)
    )""")
    op.execute("""CREATE TABLE social_approval (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES social_content_job(id) ON DELETE RESTRICT,
      content_version_id uuid NOT NULL UNIQUE REFERENCES social_content_version(id) ON DELETE RESTRICT,
      approval_public_id text NOT NULL UNIQUE, approved_by text NOT NULL,
      approved_at timestamptz NOT NULL, decision text NOT NULL,
      approval_sha256 char(64) NOT NULL UNIQUE,
      CHECK (decision IN ('approved','rejected'))
    )""")
    op.execute("""CREATE TABLE social_publication (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES social_content_job(id) ON DELETE RESTRICT,
      content_version_id uuid NOT NULL REFERENCES social_content_version(id) ON DELETE RESTRICT,
      approval_id uuid NOT NULL REFERENCES social_approval(id) ON DELETE RESTRICT,
      integration_id text NOT NULL, state text NOT NULL, postly_group_id text,
      provider_release_id text, provider_result jsonb NOT NULL DEFAULT '{}'::jsonb,
      attempt_count integer NOT NULL DEFAULT 0, next_attempt_at timestamptz,
      lease_owner text, lease_expires_at timestamptz, last_error_category text,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (job_id, content_version_id, integration_id), CHECK (attempt_count >= 0)
    )""")
    op.execute("""CREATE TABLE social_idempotency_claim (
      id uuid PRIMARY KEY, organization_id text NOT NULL, content_job_id text NOT NULL,
      content_version integer NOT NULL, integration_id text NOT NULL, scheduled_at timestamptz NOT NULL,
      claim_sha256 char(64) NOT NULL UNIQUE, publication_id uuid REFERENCES social_publication(id) ON DELETE RESTRICT,
      result jsonb, created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, content_job_id, content_version, integration_id, scheduled_at)
    )""")
    op.execute("""CREATE TABLE social_audit_record (
      id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES social_content_job(id) ON DELETE RESTRICT,
      sequence integer NOT NULL, action text NOT NULL, from_state text, to_state text NOT NULL,
      actor_ref text NOT NULL, correlation_id varchar(128) NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}'::jsonb, occurred_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (job_id, sequence)
    )""")
    op.execute("""CREATE TABLE social_delivery_attempt (
      id uuid PRIMARY KEY, publication_id uuid NOT NULL REFERENCES social_publication(id) ON DELETE RESTRICT,
      attempt_number integer NOT NULL, status text NOT NULL, safe_error_code text,
      error_category text, retryable boolean NOT NULL DEFAULT false,
      occurred_at timestamptz NOT NULL DEFAULT now(), UNIQUE (publication_id, attempt_number),
      CHECK (attempt_number >= 1)
    )""")
    op.execute("""CREATE TABLE social_dead_letter (
      id uuid PRIMARY KEY, publication_id uuid NOT NULL UNIQUE REFERENCES social_publication(id) ON DELETE RESTRICT,
      reason_code text NOT NULL, safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      replay_count integer NOT NULL DEFAULT 0, dead_lettered_at timestamptz NOT NULL DEFAULT now(),
      replayed_at timestamptz, CHECK (replay_count >= 0)
    )""")
    op.execute("""CREATE TABLE social_reconciliation_lease (
      id uuid PRIMARY KEY, publication_id uuid NOT NULL UNIQUE REFERENCES social_publication(id) ON DELETE RESTRICT,
      status text NOT NULL, lease_owner text, lease_expires_at timestamptz,
      attempt_count integer NOT NULL DEFAULT 0, next_attempt_at timestamptz,
      last_observation jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CHECK (attempt_count >= 0)
    )""")
    op.execute(
        "CREATE INDEX ix_social_job_state ON social_content_job(state, scheduled_at)"
    )
    op.execute(
        "CREATE INDEX ix_social_publication_claim ON social_publication(state, next_attempt_at, lease_expires_at)"
    )
    op.execute(
        "CREATE INDEX ix_social_reconciliation_claim ON social_reconciliation_lease(status, next_attempt_at, lease_expires_at)"
    )
    op.execute("""CREATE FUNCTION deny_social_append_only_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'append-only social evidence'; END $$""")
    for table in (
        "social_content_version",
        "social_approval",
        "social_audit_record",
        "social_delivery_attempt",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION deny_social_append_only_mutation()"
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP TABLE {table} CASCADE")
    op.execute("DROP FUNCTION deny_social_append_only_mutation()")
