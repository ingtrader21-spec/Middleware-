"""Merge the sales-foundation and deployed social-runtime migration heads."""

from __future__ import annotations


revision = "0040_merge_sales_social_heads"
down_revision = ("0036_merge_sales_n8n_heads", "0039_social_n8n_delivery")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge migration branches without changing schema."""


def downgrade() -> None:
    """Split back to the two parent migration heads without changing schema."""
