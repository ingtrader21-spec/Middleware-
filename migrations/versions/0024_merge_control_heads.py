"""Merge internal-result and control-plane migration heads.

Revision ID: 0024_merge_control_heads
Revises: 0023_internal_n8n_results, 0023_merge_control_heads
"""

revision = "0024_merge_control_heads"
down_revision = ("0023_internal_n8n_results", "0023_merge_control_heads")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Join both reviewed branches without changing schema or data."""


def downgrade() -> None:
    """Return to the two reviewed branch heads without changing schema or data."""
