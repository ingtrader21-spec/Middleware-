"""Persistent automatic campaign design and Odoo event receipts."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0058_campaign_design"
down_revision = "0057_platform_service_catalog"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "campaign_design_revision",
        sa.Column("integration_uuid", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("manifest", postgresql.JSONB, nullable=False),
        sa.Column("approval_state", sa.String(24), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("integration_uuid", "revision"),
        sa.UniqueConstraint(
            "integration_uuid",
            "revision",
            "manifest_hash",
            name="uq_campaign_revision_manifest",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_campaign_design_revision"),
        sa.CheckConstraint(
            "approval_state IN ('preview','approved')",
            name="ck_campaign_design_approval",
        ),
    )
    op.create_table(
        "campaign_design_current",
        sa.Column("integration_uuid", sa.String(64), primary_key=True),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column("odoo_campaign_id", sa.Integer, nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["integration_uuid", "revision"],
            [
                "campaign_design_revision.integration_uuid",
                "campaign_design_revision.revision",
            ],
            name="fk_campaign_current_revision",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('approval_pending','approved')",
            name="ck_campaign_current_lifecycle",
        ),
    )
    op.create_table(
        "campaign_resource_allocation",
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("reserved_identifier", sa.String(128), nullable=False),
        sa.Column("business_unit", sa.String(16), nullable=False),
        sa.Column("integration_uuid", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.UniqueConstraint(
            "environment",
            "resource_type",
            "reserved_identifier",
            name="uq_campaign_resource_identifier",
        ),
        sa.UniqueConstraint(
            "environment",
            "resource_type",
            "integration_uuid",
            "revision",
            name="uq_campaign_resource_revision",
        ),
        sa.ForeignKeyConstraint(
            ["integration_uuid", "revision"],
            [
                "campaign_design_revision.integration_uuid",
                "campaign_design_revision.revision",
            ],
            name="fk_campaign_allocation_revision",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    op.create_table(
        "campaign_event_inbox",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("integration_uuid", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("processing_state", sa.String(24), nullable=False),
        sa.Column("result_revision", sa.Integer),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "processing_state IN ('processing','completed')",
            name="ck_campaign_inbox_state",
        ),
        sa.CheckConstraint(
            "(processing_state='processing' AND result_revision IS NULL "
            "AND committed_at IS NULL) OR "
            "(processing_state='completed' AND result_revision IS NOT NULL "
            "AND committed_at IS NOT NULL)",
            name="ck_campaign_inbox_completion",
        ),
        sa.ForeignKeyConstraint(
            ["integration_uuid", "result_revision"],
            [
                "campaign_design_revision.integration_uuid",
                "campaign_design_revision.revision",
            ],
            name="fk_campaign_inbox_result",
        ),
    )
    op.create_table(
        "campaign_design_failure",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("last_error", sa.String(128), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('retry','dead_letter')",
            name="ck_campaign_failure_status",
        ),
        sa.CheckConstraint(
            "attempts >= 1",
            name="ck_campaign_failure_attempts",
        ),
    )
    op.create_table(
        "campaign_design_approval",
        sa.Column("approval_id", sa.String(36), primary_key=True),
        sa.Column("integration_uuid", sa.String(64), nullable=False),
        sa.Column("design_revision", sa.Integer, nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("approver_subject", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column(
            "approved_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.UniqueConstraint(
            "integration_uuid",
            "design_revision",
            name="uq_campaign_approval_revision",
        ),
        sa.ForeignKeyConstraint(
            ["integration_uuid", "design_revision", "manifest_hash"],
            [
                "campaign_design_revision.integration_uuid",
                "campaign_design_revision.revision",
                "campaign_design_revision.manifest_hash",
            ],
            name="fk_campaign_approval_revision",
        ),
    )
    op.execute(
        """
        CREATE FUNCTION enforce_campaign_design_revision_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'campaign design revisions are immutable';
          END IF;
          IF NEW.integration_uuid IS DISTINCT FROM OLD.integration_uuid
             OR NEW.revision IS DISTINCT FROM OLD.revision
             OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
             OR NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash
             OR NEW.manifest IS DISTINCT FROM OLD.manifest
             OR NEW.created_at IS DISTINCT FROM OLD.created_at
             OR NOT (
               OLD.approval_state = 'preview'
               AND NEW.approval_state = 'approved'
             )
          THEN
            RAISE EXCEPTION 'campaign design revisions are immutable';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER campaign_design_revision_immutable
        BEFORE UPDATE OR DELETE ON campaign_design_revision
        FOR EACH ROW
        EXECUTE FUNCTION enforce_campaign_design_revision_immutable();
        """
    )

    op.execute("""
        CREATE FUNCTION reject_campaign_approval_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'campaign design approvals are append-only';
        END;
        $$;
    """)
    op.execute("""
        CREATE TRIGGER campaign_design_approval_immutable
        BEFORE UPDATE OR DELETE ON campaign_design_approval
        FOR EACH ROW EXECUTE FUNCTION reject_campaign_approval_mutation();
    """)
    op.execute("""
        CREATE TRIGGER campaign_design_approval_no_truncate
        BEFORE TRUNCATE ON campaign_design_approval
        FOR EACH STATEMENT EXECUTE FUNCTION reject_campaign_approval_mutation();
    """)


def downgrade():
    op.drop_table("campaign_design_approval")
    op.execute("DROP FUNCTION reject_campaign_approval_mutation()")
    op.drop_table("campaign_design_failure")
    op.drop_table("campaign_event_inbox")
    op.drop_table("campaign_resource_allocation")
    op.drop_table("campaign_design_current")
    op.drop_table("campaign_design_revision")
    op.execute("DROP FUNCTION enforce_campaign_design_revision_immutable()")
