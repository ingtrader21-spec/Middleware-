"""Bind controlled test traces to the existing provisioning saga.

Revision ID: 0022_test_trace_binding
Revises: 0021_async_comm_contract
"""

import sqlalchemy as sa
from alembic import op


revision = "0022_test_trace_binding"
down_revision = "0021_async_comm_contract"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "telephony_provisioning_saga",
        sa.Column(
            "record_environment",
            sa.String(16),
            nullable=False,
            server_default="PRODUCTION",
        ),
    )
    op.add_column(
        "telephony_provisioning_saga",
        sa.Column("test_run_id", sa.String(128)),
    )
    op.add_column(
        "telephony_provisioning_saga",
        sa.Column("causation_id", sa.String(128)),
    )
    op.add_column(
        "telephony_provisioning_saga",
        sa.Column("policy_hash", sa.String(64)),
    )
    op.create_index(
        "ix_telephony_saga_test_run",
        "telephony_provisioning_saga",
        ["test_run_id"],
    )
    op.create_index(
        "ix_telephony_saga_causation",
        "telephony_provisioning_saga",
        ["causation_id"],
    )
    op.create_check_constraint(
        "ck_telephony_saga_environment",
        "telephony_provisioning_saga",
        "record_environment IN ('PRODUCTION','STAGING','TEST')",
    )
    op.create_check_constraint(
        "ck_telephony_saga_test_binding",
        "telephony_provisioning_saga",
        "(record_environment = 'PRODUCTION' AND test_run_id IS NULL) OR "
        "(record_environment IN ('STAGING','TEST') AND test_run_id IS NOT NULL "
        "AND causation_id IS NOT NULL AND policy_hash IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_telephony_saga_test_binding",
        "telephony_provisioning_saga",
        type_="check",
    )
    op.drop_constraint(
        "ck_telephony_saga_environment",
        "telephony_provisioning_saga",
        type_="check",
    )
    op.drop_index(
        "ix_telephony_saga_causation",
        table_name="telephony_provisioning_saga",
    )
    op.drop_index(
        "ix_telephony_saga_test_run",
        table_name="telephony_provisioning_saga",
    )
    for column in (
        "policy_hash",
        "causation_id",
        "test_run_id",
        "record_environment",
    ):
        op.drop_column("telephony_provisioning_saga", column)
