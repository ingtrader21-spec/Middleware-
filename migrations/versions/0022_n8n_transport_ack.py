"""Durable n8n transport, execution registration, and acknowledgement.

Revision ID: 0022_n8n_transport_ack
Revises: 0021_async_comm_contract
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0022_n8n_transport_ack"
down_revision = "0021_async_comm_contract"
branch_labels = None
depends_on = None

DELIVERY_STATES = (
    "PENDING",
    "ELIGIBILITY_VALIDATED",
    "RESERVED",
    "TARGET_ATTESTED",
    "SUBMITTING",
    "SUBMITTED",
    "ACCEPTED",
    "EXECUTION_REGISTERED",
    "ACKNOWLEDGED",
    "FAILED",
    "DEAD_LETTER",
    "RECONCILIATION_REQUIRED",
)


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    op.create_table(
        "n8n_target_attestation",
        sa.Column("attestation_id", uuid, primary_key=True),
        sa.Column("target_identity", sa.String(128), nullable=False),
        sa.Column("target_environment", sa.String(32), nullable=False),
        sa.Column("image_digest", sa.String(71), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "result IN ('PASS','FAIL')", name="ck_n8n_target_attestation_result"
        ),
    )
    op.create_table(
        "broad_event_delivery",
        sa.Column("delivery_id", uuid, primary_key=True),
        sa.Column(
            "event_id",
            sa.BigInteger,
            sa.ForeignKey("integration_event.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("workflow_id", sa.String(128), nullable=False),
        sa.Column("workflow_version", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("target_identity", sa.String(128), nullable=False),
        sa.Column("target_environment", sa.String(32), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("attempt_number", sa.Integer, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True)),
        sa.Column("response_received_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("failed_at", sa.DateTime(timezone=True)),
        sa.Column("error_class", sa.String(64)),
        sa.Column("response_hash", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "event_id",
            "workflow_id",
            "workflow_version",
            "idempotency_key",
            name="uq_broad_event_delivery_scope",
        ),
        sa.CheckConstraint("attempt_number >= 1", name="ck_broad_event_attempt"),
        sa.CheckConstraint(
            "status IN (" + ",".join(repr(value) for value in DELIVERY_STATES) + ")",
            name="ck_broad_event_delivery_status",
        ),
    )
    op.create_index(
        "ix_broad_event_delivery_status",
        "broad_event_delivery",
        ["status", "reserved_at"],
    )
    op.create_table(
        "n8n_execution_registration",
        sa.Column("execution_registration_id", uuid, primary_key=True),
        sa.Column(
            "delivery_id",
            uuid,
            sa.ForeignKey("broad_event_delivery.delivery_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("workflow_id", sa.String(128), nullable=False),
        sa.Column("workflow_version", sa.String(128), nullable=False),
        sa.Column("execution_id", sa.String(128), nullable=False, unique=True),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("response_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "status IN ('REGISTERED','QUEUED','RUNNING','SUCCEEDED','FAILED','DEAD_LETTERED')",
            name="ck_n8n_execution_status",
        ),
    )
    op.create_table(
        "n8n_acknowledgement",
        sa.Column("acknowledgement_id", uuid, primary_key=True),
        sa.Column(
            "delivery_id",
            uuid,
            sa.ForeignKey("broad_event_delivery.delivery_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("workflow_id", sa.String(128), nullable=False),
        sa.Column("workflow_version", sa.String(128), nullable=False),
        sa.Column("execution_id", sa.String(128), nullable=False, unique=True),
        sa.Column("execution_status", sa.String(24), nullable=False),
        sa.Column("result_classification", sa.String(64), nullable=False),
        sa.Column("result_hash", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("attempt_number", sa.Integer, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "persisted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "execution_status IN ('SUCCEEDED','FAILED','DEAD_LETTERED')",
            name="ck_n8n_ack_execution_status",
        ),
    )


def downgrade() -> None:
    op.drop_table("n8n_acknowledgement")
    op.drop_table("n8n_execution_registration")
    op.drop_index("ix_broad_event_delivery_status", table_name="broad_event_delivery")
    op.drop_table("broad_event_delivery")
    op.drop_table("n8n_target_attestation")
