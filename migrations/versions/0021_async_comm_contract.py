"""Complete the provider-neutral asynchronous communication contract.

Revision ID: 0021_async_comm_contract
Revises: 0020_registry_runtime_grants
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0021_async_comm_contract"
down_revision = "0020_registry_runtime_grants"
branch_labels = None
depends_on = None


NEW_STATES = (
    "REQUESTED",
    "VALIDATING",
    "VALIDATED",
    "AUTHORIZING",
    "AUTHORIZED",
    "SUPPRESSED",
    "RATE_LIMITED",
    "COST_LIMITED",
    "RESERVED",
    "QUEUED",
    "DISPATCHING",
    "PROVIDER_ACCEPTED",
    "DELIVERED",
    "DEFERRED",
    "BOUNCED",
    "COMPLAINED",
    "UNSUBSCRIBED",
    "UNDELIVERED",
    "RETRY_SCHEDULED",
    "FAILED",
    "DEAD_LETTER",
    "REPLAY_APPROVAL_REQUIRED",
    "CANCELLED",
    "EXPIRED",
    "RECONCILIATION_REQUIRED",
)

OLD_STATES = tuple(
    state
    for state in NEW_STATES
    if state not in {"DEFERRED", "BOUNCED", "COMPLAINED", "UNSUBSCRIBED", "UNDELIVERED"}
)


def _state_check(states: tuple[str, ...]) -> str:
    return "status IN (" + ",".join(repr(value) for value in states) + ")"


def upgrade():
    op.drop_constraint("ck_notification_status", "notification_command", type_="check")
    op.add_column(
        "notification_command",
        sa.Column("command_type", sa.String(64), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("customer_id", sa.String(128), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("destination_token", sa.String(256), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("destination_classification", sa.String(64), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("policy_version", sa.String(64), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("quiet_hours_policy", sa.String(128), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("rate_limit_bucket", sa.String(128), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("cost_limit_bucket", sa.String(128), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column("pii_classification", sa.String(64), nullable=False),
    )
    op.add_column(
        "notification_command",
        sa.Column(
            "template_variables",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_notification_status", "notification_command", _state_check(NEW_STATES)
    )


def downgrade():
    op.drop_constraint("ck_notification_status", "notification_command", type_="check")
    for column in (
        "template_variables",
        "pii_classification",
        "cost_limit_bucket",
        "rate_limit_bucket",
        "quiet_hours_policy",
        "policy_version",
        "destination_classification",
        "destination_token",
        "customer_id",
        "command_type",
    ):
        op.drop_column("notification_command", column)
    op.create_check_constraint(
        "ck_notification_status", "notification_command", _state_check(OLD_STATES)
    )
