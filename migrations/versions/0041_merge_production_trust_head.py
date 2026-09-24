"""Merge the production-trust and deployed social/sales migration heads."""

from __future__ import annotations


revision = "0041_merge_production_trust"
down_revision = ("0036_merge_sales_n8n_odoo", "0040_merge_sales_social_heads")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge migration branches without changing schema."""


def downgrade() -> None:
    """Split back to the two parent migration heads without changing schema."""
