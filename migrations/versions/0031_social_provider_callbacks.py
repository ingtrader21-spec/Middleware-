"""Durable replay protection for signed social provider callbacks.

Revision ID: 0031_social_provider_callbacks
Revises: 0030_social_postly_control_plane
"""

from alembic import op

revision = "0031_social_provider_callbacks"
down_revision = "0030_social_postly_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE social_provider_callback (
      callback_id uuid PRIMARY KEY, event_id text NOT NULL UNIQUE,
      job_id uuid NOT NULL REFERENCES social_content_job(id) ON DELETE RESTRICT,
      correlation_id varchar(128) NOT NULL, payload_sha256 char(64) NOT NULL,
      state text NOT NULL, attempt integer NOT NULL, occurred_at timestamptz NOT NULL,
      received_at timestamptz NOT NULL DEFAULT now(),
      CHECK (attempt >= 1)
    )""")
    op.execute(
        "CREATE INDEX ix_social_provider_callback_job ON social_provider_callback(job_id, received_at)"
    )
    op.execute("""CREATE TRIGGER social_provider_callback_append_only
      BEFORE UPDATE OR DELETE ON social_provider_callback FOR EACH ROW
      EXECUTE FUNCTION deny_social_append_only_mutation()""")


def downgrade() -> None:
    op.execute("DROP TABLE social_provider_callback")
