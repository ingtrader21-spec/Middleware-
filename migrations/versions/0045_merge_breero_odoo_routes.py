"""Merge BREERO ingress and staging Odoo delivery migration heads."""

revision = "0045_merge_breero_odoo"
down_revision = ("0044_breero_integration", "0044_merge_scraper_odoo")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge-only revision; both parent migrations contain the changes."""


def downgrade() -> None:
    """Split the graph back to both parent heads without changing data."""
