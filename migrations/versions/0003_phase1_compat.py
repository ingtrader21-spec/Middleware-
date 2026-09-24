"""restore Phase-1 tables when an existing database was unstamped"""

from alembic import op
import sqlalchemy as sa

revision = "0003_phase1_compat"
down_revision = "0002_control_plane"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.text(
            "CREATE TABLE IF NOT EXISTS integration_delivery (id UUID PRIMARY KEY, event_id BIGINT NOT NULL REFERENCES integration_event(id) ON DELETE CASCADE, target VARCHAR(32) NOT NULL, status VARCHAR(24) NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, next_attempt_at TIMESTAMPTZ, locked_at TIMESTAMPTZ, CONSTRAINT uq_delivery_event_target UNIQUE(event_id,target))"
        )
    )
    op.execute(
        sa.text(
            "CREATE TABLE IF NOT EXISTS idempotency_record (id UUID PRIMARY KEY, scope VARCHAR(100) NOT NULL, key_hash VARCHAR(64) NOT NULL, request_hash VARCHAR(64) NOT NULL, response JSONB NOT NULL, status_code INTEGER NOT NULL, event_id BIGINT REFERENCES integration_event(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), CONSTRAINT uq_idempotency_scope_key UNIQUE(scope,key_hash))"
        )
    )


def downgrade():
    op.drop_table("idempotency_record")
    op.drop_table("integration_delivery")
