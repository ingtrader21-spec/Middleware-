"""Merge 0022 heads and complete internal n8n/Odoo result contracts.

Revision ID: 0023_internal_n8n_results
Revises: 0022_n8n_transport_ack, 0022_test_trace_binding
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0023_internal_n8n_results"
down_revision = ("0022_n8n_transport_ack", "0022_test_trace_binding")
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    op.add_column(
        "n8n_target_attestation",
        sa.Column("canonical_host", sa.String(255), nullable=True),
    )
    op.add_column(
        "n8n_target_attestation",
        sa.Column("workflow_package_sha256", sa.String(64), nullable=True),
    )
    op.add_column(
        "n8n_target_attestation",
        sa.Column("request_nonce", sa.String(128), nullable=True),
    )
    op.create_unique_constraint(
        "uq_n8n_target_attestation_nonce",
        "n8n_target_attestation",
        ["request_nonce"],
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("registration_id", uuid, nullable=True),
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("idempotency_key", sa.String(255), nullable=True),
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("correlation_id", sa.String(128), nullable=True),
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("request_hash", sa.String(64), nullable=True),
    )
    op.alter_column(
        "n8n_execution_registration",
        "accepted_at",
        new_column_name="registered_at",
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_n8n_execution_registration_client_id",
        "n8n_execution_registration",
        ["registration_id"],
    )
    op.add_column(
        "n8n_acknowledgement",
        sa.Column(
            "registration_id",
            uuid,
            sa.ForeignKey(
                "n8n_execution_registration.registration_id", ondelete="RESTRICT"
            ),
            nullable=True,
        ),
    )
    op.add_column(
        "n8n_acknowledgement",
        sa.Column(
            "metrics",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_table(
        "odoo_result_delivery",
        sa.Column("result_delivery_id", uuid, primary_key=True),
        sa.Column(
            "acknowledgement_id",
            uuid,
            sa.ForeignKey("n8n_acknowledgement.acknowledgement_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("result_public_id", uuid, nullable=False, unique=True),
        sa.Column("originating_outbox_public_id", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("reserved_at", sa.DateTime(timezone=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("odoo_result_inbox_id", sa.String(64)),
        sa.Column("response_hash", sa.String(64)),
        sa.Column("last_error_class", sa.String(64)),
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
            "status IN ('PENDING','RESERVED','DELIVERED','RETRY','DEAD_LETTER')",
            name="ck_odoo_result_delivery_status",
        ),
    )
    op.create_index(
        "ix_odoo_result_delivery_claim",
        "odoo_result_delivery",
        ["status", "next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_odoo_result_delivery_claim", table_name="odoo_result_delivery")
    op.drop_table("odoo_result_delivery")
    op.drop_column("n8n_acknowledgement", "metrics")
    op.drop_column("n8n_acknowledgement", "registration_id")
    op.drop_constraint(
        "uq_n8n_execution_registration_client_id",
        "n8n_execution_registration",
        type_="unique",
    )
    op.drop_column("n8n_execution_registration", "received_at")
    op.alter_column(
        "n8n_execution_registration",
        "registered_at",
        new_column_name="accepted_at",
    )
    op.drop_column("n8n_execution_registration", "request_hash")
    op.drop_column("n8n_execution_registration", "correlation_id")
    op.drop_column("n8n_execution_registration", "idempotency_key")
    op.drop_column("n8n_execution_registration", "registration_id")
    op.drop_constraint(
        "uq_n8n_target_attestation_nonce",
        "n8n_target_attestation",
        type_="unique",
    )
    op.drop_column("n8n_target_attestation", "request_nonce")
    op.drop_column("n8n_target_attestation", "workflow_package_sha256")
    op.drop_column("n8n_target_attestation", "canonical_host")
