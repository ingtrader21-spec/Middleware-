"""Merge the sales-foundation and governed n8n/Odoo migration heads."""

from __future__ import annotations


revision = "0036_merge_sales_n8n_heads"
down_revision = ("0034_sales_lead_foundation", "0035_n8n_odoo_canary")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge migration branches without changing schema."""


def downgrade() -> None:
    """Split back to the two parent migration heads without changing schema."""
