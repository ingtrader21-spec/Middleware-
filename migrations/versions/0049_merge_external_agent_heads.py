"""Merge the externally applied webhook head with the agent runtime head.

Revision ID: 0049_merge_external_agent
Revises: 0047_external_webhooks, 0048_agent_call_realtime
"""

revision = "0049_merge_external_agent"
down_revision = ("0047_external_webhooks", "0048_agent_call_realtime")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
