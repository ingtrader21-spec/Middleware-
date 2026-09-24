"""Durable Postly polling and social n8n delivery linkage.

Revision ID: 0039_social_n8n_delivery
Revises: 0038_social_production_canary
"""

from alembic import op

revision = "0039_social_n8n_delivery"
down_revision = "0038_social_production_canary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = (
        "ALTER TABLE integration_delivery DROP CONSTRAINT ck_integration_delivery_status",
        """ALTER TABLE integration_delivery ADD CONSTRAINT ck_integration_delivery_status
        CHECK (status IN ('disabled','pending','leased','delivering','delivered',
        'retry_wait','failed','dead_letter','canceled'))""",
        """CREATE TABLE social_poll_checkpoints (
        provider text NOT NULL REFERENCES social_providers(name),
        account_id uuid NOT NULL REFERENCES social_accounts(id) ON DELETE CASCADE,
        poll_cursor text, last_updated_at timestamptz,
        last_provider_object_id text, last_success_at timestamptz,
        last_attempt_at timestamptz, status text NOT NULL DEFAULT 'READY',
        error_code text, correlation_id text NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (provider, account_id),
        CONSTRAINT ck_social_poll_checkpoint_status CHECK
          (status IN ('READY','POLLING','BACKOFF','AUTH_REQUIRED','FAILED'))
        )""",
        """CREATE TABLE social_poll_observations (
        id uuid PRIMARY KEY, provider text NOT NULL REFERENCES social_providers(name),
        account_id uuid NOT NULL REFERENCES social_accounts(id) ON DELETE CASCADE,
        provider_object_id text NOT NULL, normalized_event_type text NOT NULL,
        provider_version text NOT NULL, payload_hash char(64) NOT NULL,
        integration_event_id bigint REFERENCES integration_event(id) ON DELETE RESTRICT,
        observed_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (provider,account_id,provider_object_id,normalized_event_type,provider_version)
        )""",
        """CREATE TABLE social_n8n_delivery_execution (
        delivery_id uuid PRIMARY KEY REFERENCES integration_delivery(id) ON DELETE RESTRICT,
        execution_id uuid NOT NULL UNIQUE REFERENCES n8n_runtime_execution(execution_id) ON DELETE RESTRICT,
        created_at timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE social_n8n_delivery_attempts (
        id uuid PRIMARY KEY, delivery_id uuid NOT NULL REFERENCES integration_delivery(id) ON DELETE RESTRICT,
        attempt_number integer NOT NULL, result text NOT NULL, error_code text,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (delivery_id,attempt_number),
        CONSTRAINT ck_social_n8n_attempt_number CHECK (attempt_number > 0)
        )""",
        """CREATE TABLE social_n8n_ingress_events (
        event_id text PRIMARY KEY, execution_id uuid NOT NULL
          REFERENCES n8n_runtime_execution(execution_id) ON DELETE RESTRICT,
        delivery_id uuid NOT NULL REFERENCES integration_delivery(id) ON DELETE RESTRICT,
        body_hash char(64) NOT NULL, first_nonce text NOT NULL,
        authorized_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (execution_id), UNIQUE (delivery_id)
        )""",
        "CREATE INDEX ix_social_poll_checkpoint_status ON social_poll_checkpoints(status,last_attempt_at)",
        "CREATE INDEX ix_social_poll_observation_event ON social_poll_observations(integration_event_id)",
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP INDEX ix_social_poll_observation_event",
        "DROP INDEX ix_social_poll_checkpoint_status",
        "DROP TABLE social_n8n_delivery_attempts",
        "DROP TABLE social_n8n_ingress_events",
        "DROP TABLE social_n8n_delivery_execution",
        "DROP TABLE social_poll_observations",
        "DROP TABLE social_poll_checkpoints",
        "ALTER TABLE integration_delivery DROP CONSTRAINT ck_integration_delivery_status",
        """ALTER TABLE integration_delivery ADD CONSTRAINT ck_integration_delivery_status
        CHECK (status IN ('disabled','pending','leased','delivered','retry_wait','dead_letter','canceled'))""",
    ):
        op.execute(statement)
