"""Merge Lead Automation and recording migration branches.

Revision ID: 0029_merge_lead_recording_heads
Revises: 0028_lead_automation_v1, 0028_recording_api
"""

revision = "0029_merge_lead_recording_heads"
down_revision = (
    "0028_lead_automation_v1",
    "0028_recording_api",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Join the two valid branches without changing schema or data."""


def downgrade() -> None:
    """Return topology to the two parent heads without changing schema or data."""
