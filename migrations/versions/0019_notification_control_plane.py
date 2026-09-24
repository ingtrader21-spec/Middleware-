"""Add provider-neutral notification control-plane journal.

Revision ID: 0019_notification_control_plane
Revises: 0018_campaign_search_aliases
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0019_notification_control_plane"
down_revision = "0018_campaign_search_aliases"
branch_labels = None
depends_on = None


def upgrade():
    command_states = (
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
        "RETRY_SCHEDULED",
        "FAILED",
        "DEAD_LETTER",
        "REPLAY_APPROVAL_REQUIRED",
        "CANCELLED",
        "EXPIRED",
        "RECONCILIATION_REQUIRED",
    )
    op.create_table(
        "notification_command",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("command_id", sa.String(128), nullable=False, unique=True),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("causation_id", sa.String(128)),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("business_unit_id", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(128), nullable=False),
        sa.Column("lead_id", sa.String(128)),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("template_id", sa.String(128), nullable=False),
        sa.Column("template_version", sa.Integer, nullable=False),
        sa.Column("sender_profile_id", sa.String(128), nullable=False),
        sa.Column("consent_evidence_id", sa.String(128), nullable=False),
        sa.Column("suppression_version", sa.String(128), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("approved_by", sa.String(128)),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="REQUESTED"),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("policy_decision", sa.String(40)),
        sa.Column("provider_message_id", sa.String(256)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "channel IN ('EMAIL','SMS')", name="ck_notification_channel"
        ),
        sa.CheckConstraint(
            "status IN (" + ",".join(repr(value) for value in command_states) + ")",
            name="ck_notification_status",
        ),
        sa.CheckConstraint(
            "template_version > 0", name="ck_notification_template_version"
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_notification_attempt_count"),
        sa.CheckConstraint("expires_at > requested_at", name="ck_notification_expiry"),
        sa.UniqueConstraint(
            "organization_id",
            "business_unit_id",
            "channel",
            "idempotency_key",
            name="uq_notification_idempotency_scope",
        ),
    )
    op.create_index(
        "ix_notification_command_claim",
        "notification_command",
        ["status", "not_before", "created_at"],
    )
    op.create_index(
        "ix_notification_command_correlation",
        "notification_command",
        ["correlation_id"],
    )
    op.create_table(
        "notification_attempt",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "command_id",
            sa.String(128),
            sa.ForeignKey("notification_command.command_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("attempt_number", sa.Integer, nullable=False),
        sa.Column("reservation_id", sa.String(128), nullable=False, unique=True),
        sa.Column("provider", sa.String(64)),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("result_code", sa.String(64)),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("attempt_number > 0", name="ck_notification_attempt_number"),
        sa.UniqueConstraint(
            "command_id", "attempt_number", name="uq_notification_attempt_number"
        ),
    )
    op.create_table(
        "notification_replay_approval",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "command_id",
            sa.String(128),
            sa.ForeignKey("notification_command.command_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("approved_by", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("approval_hash", sa.String(64), nullable=False, unique=True),
        sa.CheckConstraint(
            "expires_at > approved_at", name="ck_notification_replay_expiry"
        ),
    )


def downgrade():
    op.drop_table("notification_replay_approval")
    op.drop_table("notification_attempt")
    op.drop_index(
        "ix_notification_command_correlation", table_name="notification_command"
    )
    op.drop_index("ix_notification_command_claim", table_name="notification_command")
    op.drop_table("notification_command")
