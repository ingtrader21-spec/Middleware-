"""CRM/VICIdial durable identity and reconciliation guards."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006_lead_reconciliation"
down_revision = "0005_durable_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    ts = sa.DateTime(timezone=True)
    op.create_table(
        "vicidial_identity_map",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("company_id", sa.String(64), nullable=False),
        sa.Column("environment_id", sa.String(64), nullable=False),
        sa.Column("connector_id", sa.String(64), nullable=False),
        sa.Column("odoo_model", sa.String(64), nullable=False),
        sa.Column("odoo_record_id", sa.BigInteger, nullable=False),
        sa.Column("external_entity_type", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("external_parent_id", sa.String(128)),
        sa.Column("payload_checksum", sa.String(64)),
        sa.Column("source_revision", sa.String(128)),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_synced_at", ts),
        sa.Column("last_verified_at", ts),
        sa.CheckConstraint(
            "external_entity_type <> 'list_membership' OR external_parent_id IS NOT NULL",
            name="ck_vicidial_membership_parent_required",
        ),
    )
    op.create_index(
        "uq_vicidial_map_odoo_lead_active",
        "vicidial_identity_map",
        [
            "connector_id",
            "environment_id",
            "odoo_model",
            "odoo_record_id",
            "external_entity_type",
        ],
        unique=True,
        postgresql_where=sa.text("active AND external_entity_type = 'lead'"),
    )
    op.create_index(
        "uq_vicidial_map_odoo_membership_active",
        "vicidial_identity_map",
        [
            "connector_id",
            "environment_id",
            "odoo_model",
            "odoo_record_id",
            "external_entity_type",
            "external_parent_id",
        ],
        unique=True,
        postgresql_where=sa.text("active AND external_entity_type = 'list_membership'"),
    )
    op.create_index(
        "uq_vicidial_map_external_active",
        "vicidial_identity_map",
        ["connector_id", "environment_id", "external_entity_type", "external_id"],
        unique=True,
        postgresql_where=sa.text("active"),
    )
    op.create_table(
        "vicidial_sync_run",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("company_id", sa.String(64), nullable=False),
        sa.Column("connector_id", sa.String(64), nullable=False),
        sa.Column("started_at", ts, nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", ts),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("source_cursor", ts),
        sa.Column("next_cursor", ts),
        sa.Column(
            "counts",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_summary", sa.Text),
    )
    op.create_index(
        "uq_vicidial_sync_run_active",
        "vicidial_sync_run",
        ["company_id", "connector_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_table(
        "vicidial_sync_action",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "sync_run_id", uuid, sa.ForeignKey("vicidial_sync_run.id"), nullable=False
        ),
        sa.Column("idempotency_key", sa.String(512), nullable=False, unique=True),
        sa.Column("request_checksum", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("external_id", sa.String(128)),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("created_at", ts, nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", ts),
        sa.Column("error_summary", sa.Text),
    )
    op.create_table(
        "vicidial_reconciliation_issue",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("company_id", sa.String(64), nullable=False),
        sa.Column("connector_id", sa.String(64), nullable=False),
        sa.Column("issue_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("evidence", postgresql.JSONB, nullable=False),
        sa.Column("created_at", ts, nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", ts),
    )


def downgrade() -> None:
    op.drop_table("vicidial_reconciliation_issue")
    op.drop_table("vicidial_sync_action")
    op.drop_index("uq_vicidial_sync_run_active", table_name="vicidial_sync_run")
    op.drop_table("vicidial_sync_run")
    op.drop_index("uq_vicidial_map_external_active", table_name="vicidial_identity_map")
    op.drop_index(
        "uq_vicidial_map_odoo_membership_active", table_name="vicidial_identity_map"
    )
    op.drop_index(
        "uq_vicidial_map_odoo_lead_active", table_name="vicidial_identity_map"
    )
    op.drop_table("vicidial_identity_map")
