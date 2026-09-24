"""Merge n8n acknowledgement and test-trace migration heads.

Revision ID: 0023_merge_control_heads
Revises: 0022_n8n_transport_ack, 0022_test_trace_binding
"""

revision = "0023_merge_control_heads"
down_revision = ("0022_n8n_transport_ack", "0022_test_trace_binding")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Join both reviewed branches without changing schema or data."""


def downgrade() -> None:
    """Return to the two reviewed branch heads without changing schema or data."""
