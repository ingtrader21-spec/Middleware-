"""Add the versioned fail-closed VICIdial campaign mapping registry.

Revision ID: 0009_vicidial_campaign_registry
Revises: 0008_orchestration
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0009_vicidial_campaign_registry"
down_revision = "0008_orchestration"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vicidial_campaign_registry",
        sa.Column("mapping_uuid", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("mapping_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("business_unit_code", sa.String(3), nullable=False),
        sa.Column("odoo_business_unit_uuid", postgresql.UUID(as_uuid=True)),
        sa.Column("odoo_crm_team_uuid", postgresql.UUID(as_uuid=True)),
        sa.Column("odoo_campaign_uuid", postgresql.UUID(as_uuid=True)),
        sa.Column("canonical_campaign_code", sa.String(64), nullable=False),
        sa.Column("campaign_family", sa.String(32)),
        sa.Column("direction", sa.String(3), nullable=False),
        sa.Column("vicidial_campaign_id", sa.String(8), nullable=False),
        sa.Column("default_list_id", sa.BigInteger()),
        sa.Column("default_user_group", sa.String(20)),
        sa.Column("default_inbound_group", sa.String(20)),
        sa.Column("default_closer_group", sa.String(20)),
        sa.Column("default_support_group", sa.String(20)),
        sa.Column("default_retention_group", sa.String(20)),
        sa.Column("asterisk_context", sa.String(80)),
        sa.Column("ivr_route_code", sa.String(64)),
        sa.Column("did_mapping_code", sa.String(64)),
        sa.Column("script_code", sa.String(20)),
        sa.Column("script_version", sa.Integer()),
        sa.Column("disposition_set_code", sa.String(64)),
        sa.Column("disposition_set_version", sa.Integer()),
        sa.Column("recording_policy_code", sa.String(64)),
        sa.Column("consent_policy_code", sa.String(64)),
        sa.Column("calling_hours_policy_code", sa.String(64)),
        sa.Column("appointment_policy_code", sa.String(64)),
        sa.Column("n8n_scope", sa.String(128)),
        sa.Column(
            "feature_flag_set",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("desired_state_hash", sa.String(64), nullable=False),
        sa.Column("observed_state_hash", sa.String(64)),
        sa.Column("last_applied_at", sa.DateTime(timezone=True)),
        sa.Column("last_read_back_at", sa.DateTime(timezone=True)),
        sa.Column(
            "drift_status", sa.String(24), nullable=False, server_default="not_observed"
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
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
            "schema_version > 0", name="ck_vicidial_registry_schema_version"
        ),
        sa.CheckConstraint(
            "mapping_version > 0", name="ck_vicidial_registry_mapping_version"
        ),
        sa.CheckConstraint(
            "environment IN ('development','staging','production')",
            name="ck_vicidial_registry_environment",
        ),
        sa.CheckConstraint(
            "business_unit_code IN ('MOY','COD','SCP','MBL','RLP','FTP','TRX','CAL')",
            name="ck_vicidial_registry_business_unit",
        ),
        sa.CheckConstraint(
            "direction IN ('IN','OUT')", name="ck_vicidial_registry_direction"
        ),
        sa.CheckConstraint(
            "vicidial_campaign_id ~ '^[A-Z0-9]{8}$'",
            name="ck_vicidial_registry_physical_id",
        ),
        sa.CheckConstraint(
            "NOT (environment = 'production' AND active)",
            name="ck_vicidial_registry_production_inactive",
        ),
        sa.UniqueConstraint(
            "environment",
            "canonical_campaign_code",
            name="uq_vicidial_registry_canonical_environment",
        ),
        sa.UniqueConstraint(
            "vicidial_campaign_id", name="uq_vicidial_registry_physical_id"
        ),
    )


def downgrade():
    op.drop_table("vicidial_campaign_registry")
