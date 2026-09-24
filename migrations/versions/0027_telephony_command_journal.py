"""Add telephony command and operation journals.

Revision ID: 0027_telephony_command_journal
Revises: 0026_n8n_contracts
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0027_telephony_command_journal"
down_revision = "0026_n8n_contracts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    op.create_table(
        "telephony_command_journal",
        sa.Column("command_id", uuid, nullable=False),
        sa.Column("command_public_id", sa.String(144), nullable=False),
        sa.Column("command_type", sa.String(96), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False),
        sa.Column("aggregate_public_id", sa.String(144), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("business_unit_public_id", sa.String(144), nullable=False),
        sa.Column("campaign_public_id", sa.String(144), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("causation_id", sa.String(128), nullable=False),
        sa.Column("policy_decision_id", sa.String(144), nullable=False),
        sa.Column("policy_decision_hash", sa.String(64), nullable=False),
        sa.Column("payload_json", jsonb, nullable=False),
        sa.Column("request_json", jsonb, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "aggregate_version >= 1", name="ck_telephony_command_version"
        ),
        sa.CheckConstraint(
            "environment IN ('staging','test','production')",
            name="ck_telephony_command_environment",
        ),
        sa.PrimaryKeyConstraint("command_id"),
        sa.UniqueConstraint("command_public_id"),
        sa.UniqueConstraint("idempotency_hash"),
        sa.UniqueConstraint(
            "environment",
            "aggregate_type",
            "aggregate_public_id",
            "aggregate_version",
            name="uq_telephony_command_aggregate_version",
        ),
    )
    op.create_index(
        "ix_telephony_command_aggregate",
        "telephony_command_journal",
        ["aggregate_type", "aggregate_public_id", "aggregate_version"],
    )
    op.create_index(
        "ix_telephony_command_correlation",
        "telephony_command_journal",
        ["correlation_id"],
    )
    op.create_table(
        "telephony_operation_journal",
        sa.Column("operation_id", uuid, nullable=False),
        sa.Column("operation_public_id", sa.String(144), nullable=False),
        sa.Column("command_id", uuid, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("adapter_service_key", sa.String(144), nullable=False),
        sa.Column("adapter_operation_id", sa.String(144), nullable=False),
        sa.Column("target_system", sa.String(32), nullable=False),
        sa.Column("target_resource_type", sa.String(32), nullable=False),
        sa.Column("target_public_id", sa.String(144), nullable=False),
        sa.Column("desired_state_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=False),
        sa.Column(
            "transition_sequence", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("endpoint_key", sa.String(96), nullable=False),
        sa.Column("readback_endpoint_key", sa.String(96), nullable=False),
        sa.Column("target_configuration_checksum", sa.String(71), nullable=False),
        sa.Column("target_attested", sa.Boolean(), nullable=False),
        sa.Column("desired_hash", sa.String(64), nullable=False),
        sa.Column("actual_hash", sa.String(64), nullable=True),
        sa.Column("readback_matches", sa.Boolean(), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("response_json", jsonb, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(readback_matches IS NOT TRUE) OR (actual_hash IS NOT NULL)",
            name="ck_telephony_operation_readback_hash",
        ),
        sa.ForeignKeyConstraint(
            ["command_id"],
            ["telephony_command_journal.command_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint("operation_public_id"),
        sa.UniqueConstraint("idempotency_hash"),
        sa.UniqueConstraint("command_id"),
    )
    op.create_index(
        "ix_telephony_operation_correlation",
        "telephony_operation_journal",
        ["correlation_id"],
    )
    op.create_table(
        "telephony_operation_transition",
        sa.Column("transition_id", uuid, nullable=False),
        sa.Column("operation_id", uuid, nullable=False),
        sa.Column("command_id", uuid, nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=False),
        sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("transition_hash", sa.String(64), nullable=False),
        sa.Column("binding_json", jsonb, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["telephony_operation_journal.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["command_id"],
            ["telephony_command_journal.command_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("transition_id"),
        sa.UniqueConstraint(
            "operation_id", "sequence", name="uq_telephony_transition_sequence"
        ),
        sa.UniqueConstraint(
            "operation_id",
            "transition_hash",
            name="uq_telephony_transition_hash",
        ),
    )
    op.create_table(
        "telephony_terminal_result",
        sa.Column("result_id", uuid, nullable=False),
        sa.Column("result_public_id", sa.String(144), nullable=False),
        sa.Column("operation_id", uuid, nullable=False),
        sa.Column("command_id", uuid, nullable=False),
        sa.Column("result_hash", sa.String(64), nullable=False),
        sa.Column("application_hash", sa.String(64), nullable=False),
        sa.Column("readback_hash", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("target_system", sa.String(32), nullable=False),
        sa.Column("target_resource_type", sa.String(32), nullable=False),
        sa.Column("target_public_id", sa.String(144), nullable=False),
        sa.Column("requested_state_version", sa.Integer(), nullable=False),
        sa.Column("applied_state_version", sa.Integer(), nullable=False),
        sa.Column("observed_state_version", sa.Integer(), nullable=False),
        sa.Column("application_status", sa.String(32), nullable=False),
        sa.Column("readback_status", sa.String(32), nullable=False),
        sa.Column("adapter_service_key", sa.String(144), nullable=False),
        sa.Column("adapter_configuration_checksum", sa.String(71), nullable=False),
        sa.Column("safe_summary", sa.String(512), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("readback_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "odoo_callback_status",
            sa.String(32),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reconciliation_status", sa.String(32), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("immutable_json", jsonb, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["telephony_operation_journal.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["command_id"],
            ["telephony_command_journal.command_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("result_id"),
        sa.UniqueConstraint("result_public_id"),
        sa.UniqueConstraint("operation_id"),
        sa.UniqueConstraint(
            "result_hash", "operation_id", name="uq_telephony_result_binding"
        ),
    )
    op.create_index(
        "ix_telephony_result_correlation",
        "telephony_terminal_result",
        ["correlation_id"],
    )
    op.create_table(
        "telephony_reconciliation_run",
        sa.Column("run_id", uuid, nullable=False),
        sa.Column("run_public_id", sa.String(144), nullable=False),
        sa.Column("command_id", uuid, nullable=True),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False),
        sa.Column("aggregate_public_id", sa.String(144), nullable=False),
        sa.Column("target_system", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("classification", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("evidence_json", jsonb, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["command_id"],
            ["telephony_command_journal.command_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint("run_public_id"),
    )
    op.create_index(
        "ix_telephony_reconciliation_correlation",
        "telephony_reconciliation_run",
        ["correlation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_telephony_reconciliation_correlation",
        table_name="telephony_reconciliation_run",
    )
    op.drop_table("telephony_reconciliation_run")
    op.drop_index(
        "ix_telephony_result_correlation",
        table_name="telephony_terminal_result",
    )
    op.drop_table("telephony_terminal_result")
    op.drop_table("telephony_operation_transition")
    op.drop_index(
        "ix_telephony_operation_correlation",
        table_name="telephony_operation_journal",
    )
    op.drop_table("telephony_operation_journal")
    op.drop_index(
        "ix_telephony_command_correlation", table_name="telephony_command_journal"
    )
    op.drop_index(
        "ix_telephony_command_aggregate", table_name="telephony_command_journal"
    )
    op.drop_table("telephony_command_journal")
