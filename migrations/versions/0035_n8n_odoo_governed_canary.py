"""Bind governed n8n results to the existing durable Odoo result delivery.

Revision ID: 0035_n8n_odoo_canary
Revises: 0034_n8n_redis_runtime
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0035_n8n_odoo_canary"
down_revision = "0034_n8n_redis_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    op.alter_column("odoo_result_delivery", "acknowledgement_id", nullable=True)
    op.add_column(
        "odoo_result_delivery",
        sa.Column(
            "runtime_result_id",
            uuid,
            sa.ForeignKey("n8n_runtime_result.result_id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.create_unique_constraint(
        "uq_odoo_result_delivery_runtime_result",
        "odoo_result_delivery",
        ["runtime_result_id"],
    )
    op.create_check_constraint(
        "ck_odoo_result_delivery_one_source",
        "odoo_result_delivery",
        "(acknowledgement_id IS NOT NULL) <> (runtime_result_id IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_odoo_result_delivery_one_source",
        "odoo_result_delivery",
        type_="check",
    )
    op.drop_constraint(
        "uq_odoo_result_delivery_runtime_result",
        "odoo_result_delivery",
        type_="unique",
    )
    op.drop_column("odoo_result_delivery", "runtime_result_id")
    op.alter_column("odoo_result_delivery", "acknowledgement_id", nullable=False)
