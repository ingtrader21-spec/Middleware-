"""Complete canonical n8n registration, transition and acknowledgement contracts.

Revision ID: 0026_n8n_contracts
Revises: 0025_endpoint_registry
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0026_n8n_contracts"
down_revision = "0025_endpoint_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    op.drop_constraint(
        "ck_broad_event_delivery_status",
        "broad_event_delivery",
        type_="check",
    )
    op.create_check_constraint(
        "ck_broad_event_delivery_status",
        "broad_event_delivery",
        "status IN ("
        "'PENDING','ELIGIBILITY_VALIDATED','RESERVED','TARGET_ATTESTED',"
        "'SUBMITTING','SUBMITTED','ACCEPTED','EXECUTION_REGISTERED','RUNNING',"
        "'ACKNOWLEDGED','RESULT_PENDING','RESULT_DELIVERED',"
        "'RECONCILIATION_REQUIRED','RECONCILED','FAILED_TRANSIENT',"
        "'FAILED_PERMANENT','FAILED','DEAD_LETTER'"
        ")",
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("policy_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "n8n_execution_registration",
        sa.Column("attempt_number", sa.Integer(), nullable=True),
    )
    op.execute(
        """
        UPDATE n8n_execution_registration AS registration
        SET policy_hash = delivery.policy_hash,
            attempt_number = delivery.attempt_number
        FROM broad_event_delivery AS delivery
        WHERE delivery.delivery_id = registration.delivery_id
        """
    )
    op.alter_column("n8n_execution_registration", "policy_hash", nullable=False)
    op.alter_column("n8n_execution_registration", "attempt_number", nullable=False)
    op.create_check_constraint(
        "ck_n8n_registration_attempt",
        "n8n_execution_registration",
        "attempt_number >= 1 AND attempt_number <= 8",
    )
    op.create_table(
        "n8n_execution_transition",
        sa.Column("transition_id", uuid, primary_key=True),
        sa.Column(
            "registration_id",
            uuid,
            sa.ForeignKey(
                "n8n_execution_registration.registration_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(24), nullable=False),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "persisted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "registration_id",
            "to_status",
            name="uq_n8n_transition_registration_status",
        ),
        sa.CheckConstraint(
            "from_status IN ('REGISTERED','RUNNING')",
            name="ck_n8n_transition_from_status",
        ),
        sa.CheckConstraint(
            "to_status IN ('RUNNING','SUCCEEDED','FAILED','DEAD_LETTERED')",
            name="ck_n8n_transition_to_status",
        ),
        sa.CheckConstraint(
            "attempt_number >= 1 AND attempt_number <= 8",
            name="ck_n8n_transition_attempt",
        ),
    )
    op.create_index(
        "ix_n8n_transition_registration",
        "n8n_execution_transition",
        ["registration_id", "persisted_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_n8n_transition_registration",
        table_name="n8n_execution_transition",
    )
    op.drop_table("n8n_execution_transition")
    op.drop_constraint(
        "ck_n8n_registration_attempt",
        "n8n_execution_registration",
        type_="check",
    )
    op.drop_column("n8n_execution_registration", "attempt_number")
    op.drop_column("n8n_execution_registration", "policy_hash")
    op.drop_constraint(
        "ck_broad_event_delivery_status",
        "broad_event_delivery",
        type_="check",
    )
    op.create_check_constraint(
        "ck_broad_event_delivery_status",
        "broad_event_delivery",
        "status IN ("
        "'PENDING','ELIGIBILITY_VALIDATED','RESERVED','TARGET_ATTESTED',"
        "'SUBMITTING','SUBMITTED','ACCEPTED','EXECUTION_REGISTERED',"
        "'ACKNOWLEDGED','FAILED','DEAD_LETTER','RECONCILIATION_REQUIRED'"
        ")",
    )
