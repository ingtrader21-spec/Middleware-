"""Merge scraper inbox and staging Odoo registry heads.

Revision ID: 0044_merge_scraper_odoo
Revises: 0043_scraper_durable_inbox, 0043_staging_odoo_routes
"""

revision = "0044_merge_scraper_odoo"
down_revision = ("0043_scraper_durable_inbox", "0043_staging_odoo_routes")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Lineage-only merge."""


def downgrade() -> None:
    """Lineage-only merge."""
