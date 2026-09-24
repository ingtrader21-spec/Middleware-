"""Seed exact campaign search aliases.

Revision ID: 0018_campaign_search_aliases
Revises: 0017_campaign_registry_seed
"""

from alembic import op


revision = "0018_campaign_search_aliases"
down_revision = "0017_campaign_registry_seed"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        INSERT INTO campaign_search_alias(alias,campaign_number,alias_type)
        SELECT alias,campaign_number,alias_type
        FROM (
          SELECT campaign_number, campaign_number::text AS alias,
                 'CAMPAIGN_NUMBER' AS alias_type
          FROM campaign_registry
          UNION ALL
          SELECT campaign_number, campaign_code, 'CAMPAIGN_CODE'
          FROM campaign_registry
          UNION ALL
          SELECT campaign_number, campaign_public_id, 'CAMPAIGN_PUBLIC_ID'
          FROM campaign_registry
          UNION ALL
          SELECT campaign_number, vicidial_campaign_id, 'VICIDIAL_CAMPAIGN_ID'
          FROM campaign_registry
        ) aliases
        ON CONFLICT (alias) DO NOTHING
        """
    )


def downgrade():
    raise RuntimeError("canonical search aliases are permanent and non-reusable")
