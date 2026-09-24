"""Provider-neutral social publishing foundation.

Revision ID: 0036_social_publishing
Revises: 0035_n8n_odoo_canary
"""

from alembic import op

revision = "0036_social_publishing"
down_revision = "0035_n8n_odoo_canary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = (
        """CREATE TABLE social_providers (
        name text PRIMARY KEY, enabled boolean NOT NULL DEFAULT false,
        configured boolean NOT NULL DEFAULT false, capabilities jsonb NOT NULL DEFAULT '[]',
        metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_social_provider_name CHECK (name IN ('postly','hootsuite','buffer','direct_meta','direct_linkedin','direct_tiktok','direct_youtube')))""",
        """CREATE TABLE social_accounts (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, provider text NOT NULL REFERENCES social_providers(name),
        provider_account_id text NOT NULL, network text NOT NULL, external_profile_name text NOT NULL,
        external_profile_id text NOT NULL, connection_state text NOT NULL, capabilities jsonb NOT NULL DEFAULT '[]',
        metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(), last_sync_at timestamptz,
        CONSTRAINT uq_social_account_external UNIQUE (tenant_id,provider,provider_account_id),
        CONSTRAINT ck_social_network CHECK (network IN ('facebook','instagram','linkedin','x','tiktok','youtube','pinterest','threads','google_business','other')))""",
        """CREATE TABLE social_campaigns (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL, status text NOT NULL DEFAULT 'DRAFT',
        metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())""",
        """CREATE TABLE social_media_assets (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, media_type text NOT NULL, content_type text NOT NULL,
        storage_reference text NOT NULL, checksum_sha256 char(64) NOT NULL, metadata jsonb NOT NULL DEFAULT '{}',
        created_at timestamptz NOT NULL DEFAULT now())""",
        """CREATE TABLE social_posts (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, campaign_id uuid REFERENCES social_campaigns(id),
        provider text NOT NULL REFERENCES social_providers(name), provider_post_id text,
        status text NOT NULL, content jsonb NOT NULL, publish_at timestamptz, metadata jsonb NOT NULL DEFAULT '{}',
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_social_post_provider_ref UNIQUE (provider,provider_post_id),
        CONSTRAINT ck_social_post_status CHECK (status IN ('DRAFT','QUEUED','SCHEDULED','PUBLISHING','PUBLISHED','FAILED','CANCELLED','DELETED','REQUIRES_ACTION','UNKNOWN')))""",
        """CREATE TABLE social_post_accounts (
        social_post_id uuid NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE,
        social_account_id uuid NOT NULL REFERENCES social_accounts(id), PRIMARY KEY (social_post_id,social_account_id))""",
        """CREATE TABLE social_publish_jobs (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, social_post_id uuid NOT NULL REFERENCES social_posts(id),
        provider text NOT NULL REFERENCES social_providers(name), job_type text NOT NULL, state text NOT NULL DEFAULT 'queued',
        attempt_count integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 5,
        correlation_id text NOT NULL, request_id text NOT NULL, idempotency_key text NOT NULL,
        next_attempt_at timestamptz, locked_at timestamptz, last_error_code text, last_error_summary text,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), failed_at timestamptz,
        CONSTRAINT uq_social_job_idempotency UNIQUE (tenant_id,job_type,social_post_id,idempotency_key),
        CONSTRAINT ck_social_job_attempts CHECK (attempt_count >= 0 AND max_attempts > 0))""",
        """CREATE TABLE social_publish_attempts (
        id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES social_publish_jobs(id), attempt_number integer NOT NULL,
        result text NOT NULL, error_code text, error_summary text, provider_request_id text,
        duration_ms integer, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(job_id,attempt_number))""",
        """CREATE TABLE social_webhook_events (
        id uuid PRIMARY KEY, provider text NOT NULL REFERENCES social_providers(name), provider_event_id text NOT NULL,
        payload_hash char(64) NOT NULL, signature_valid boolean NOT NULL, state text NOT NULL DEFAULT 'accepted',
        correlation_id text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), processed_at timestamptz,
        safe_payload jsonb NOT NULL DEFAULT '{}', UNIQUE(provider,provider_event_id))""",
        """CREATE TABLE social_provider_events (
        id uuid PRIMARY KEY, webhook_event_id uuid REFERENCES social_webhook_events(id), event_type text NOT NULL,
        event_version integer NOT NULL DEFAULT 1, occurred_at timestamptz NOT NULL, correlation_id text NOT NULL,
        tenant_id uuid NOT NULL, provider text NOT NULL REFERENCES social_providers(name), subject_id uuid NOT NULL,
        payload jsonb NOT NULL DEFAULT '{}', dispatched_at timestamptz)""",
        """CREATE TABLE social_analytics_snapshots (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, social_post_id uuid REFERENCES social_posts(id),
        social_account_id uuid REFERENCES social_accounts(id), provider text NOT NULL REFERENCES social_providers(name),
        captured_at timestamptz NOT NULL, metrics jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now())""",
        """CREATE TABLE social_audit_events (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, actor_type text NOT NULL, actor_id text NOT NULL,
        action text NOT NULL, social_post_id uuid REFERENCES social_posts(id), campaign_id uuid REFERENCES social_campaigns(id),
        provider text, account_id uuid REFERENCES social_accounts(id), correlation_id text NOT NULL, request_id text NOT NULL,
        job_id uuid, idempotency_key_hash char(64), result text NOT NULL, error_code text,
        metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now())""",
        "CREATE INDEX ix_social_jobs_claim ON social_publish_jobs(state,next_attempt_at,created_at)",
        "CREATE INDEX ix_social_posts_tenant_created ON social_posts(tenant_id,created_at DESC)",
        "CREATE INDEX ix_social_events_dispatch ON social_provider_events(dispatched_at,occurred_at)",
        "INSERT INTO social_providers(name) VALUES ('postly'),('hootsuite')",
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for table in (
        "social_audit_events",
        "social_analytics_snapshots",
        "social_provider_events",
        "social_webhook_events",
        "social_publish_attempts",
        "social_publish_jobs",
        "social_post_accounts",
        "social_posts",
        "social_media_assets",
        "social_campaigns",
        "social_accounts",
        "social_providers",
    ):
        op.execute(f"DROP TABLE {table}")
