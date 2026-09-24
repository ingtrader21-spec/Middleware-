"""Add lead_model/lead_id to telephony_call_lifecycle.

POST /v1/telephony/calls/originate already receives lead_model/lead_id in
its request body and records them into AuditEvent.redacted_payload, but
never onto telephony_call_lifecycle itself - the row GET /platform/v1/calls
actually reads. Odoo/codestra_middleware_bridge remains the system of
record for the lead/customer-profile record itself; these two columns are
only an immutable reference captured at originate time.

Revision ID: 0063_telephony_lead_reference
Revises: 0062_merge_telnexa_kyyow
"""

from alembic import op

revision = "0063_telephony_lead_reference"
down_revision = "0062_merge_telnexa_kyyow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE telephony_call_lifecycle "
        "ADD COLUMN lead_model varchar(64), "
        "ADD COLUMN lead_id integer"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE telephony_call_lifecycle "
        "DROP COLUMN lead_model, "
        "DROP COLUMN lead_id"
    )
