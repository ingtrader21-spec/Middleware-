"""Merge the deployed gateway lineage with the production-trust lineage.

Revision ID: 0042_merge_gateway_trust
Revises: 0033_event_model_compatibility, 0041_merge_production_trust
"""

revision = "0042_merge_gateway_trust"
down_revision = (
    "0033_event_model_compatibility",
    "0041_merge_production_trust",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Lineage-only merge; both parent migrations remain authoritative."""


def downgrade() -> None:
    """Lineage-only merge; downgrading restores both parent heads."""
