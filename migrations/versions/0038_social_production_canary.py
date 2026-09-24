"""Production canary execution evidence.

Revision ID: 0038_social_production_canary
Revises: 0037_social_staging
"""

from alembic import op

revision = "0038_social_production_canary"
down_revision = "0037_social_staging"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""ALTER TABLE social_publish_jobs
        ADD COLUMN production_canary boolean NOT NULL DEFAULT false,
        ADD COLUMN production_account_id uuid REFERENCES social_accounts(id),
        ADD COLUMN content_approved_at timestamptz""")
    op.execute(
        "CREATE INDEX ix_social_jobs_production_canary ON social_publish_jobs(production_canary,state,created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX ix_social_jobs_production_canary")
    op.execute("""ALTER TABLE social_publish_jobs
        DROP COLUMN content_approved_at,
        DROP COLUMN production_account_id,
        DROP COLUMN production_canary""")
