"""Add immutable campaign registry, scoped identities, and search aliases.

Revision ID: 0016_campaign_registry_ids
Revises: 0015_campaign_ext_allocation
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0016_campaign_registry_ids"
down_revision = "0015_campaign_ext_allocation"
branch_labels = None
depends_on = None

CAMPAIGNS = (
    (
        100,
        "RLP International Real Estate",
        "RLP",
        "RLP100",
        7100,
        7199,
        "RLP100_AGENTS",
        "cs-prod-rlp100",
        None,
    ),
    (
        200,
        "TradeX",
        "TRD",
        "TRD200",
        7200,
        7299,
        "TRD200_AGENTS",
        "cs-prod-trd200",
        None,
    ),
    (
        300,
        "Moy Logistics",
        "MOY",
        "MOY300",
        7300,
        7399,
        "MOY300_AGENTS",
        "cs-prod-moy300",
        None,
    ),
    (
        400,
        "Codestra",
        "COD",
        "COD400",
        7400,
        7499,
        "COD400_AGENTS",
        "cs-prod-cod400",
        None,
    ),
    (
        500,
        "Senior Citizen Products",
        "SCP",
        "SCP500",
        7500,
        7599,
        "SCP500_AGENTS",
        "cs-prod-scp500",
        None,
    ),
    (
        600,
        "MoneyBee Business Loans",
        "MBL",
        "MBL600",
        7600,
        7699,
        "MBL600_AGENTS",
        "cs-prod-mbl600",
        None,
    ),
    (
        700,
        "For the People",
        "FTP",
        "FTP700",
        7700,
        7799,
        "FTP700_AGENTS",
        "cs-prod-ftp700",
        None,
    ),
    (
        800,
        "Calderon Farm",
        "CAL",
        "CAL800",
        7800,
        7899,
        "CAL800_AGENTS",
        "cs-prod-cal800",
        300,
    ),
)


def upgrade():
    # PostgreSQL sequences are intentionally non-transactional: a rolled-back
    # issuance leaves a gap and can never cause identifier reuse.
    op.execute("CREATE SEQUENCE campaign_identity_global_seq AS bigint START 1")
    op.create_table(
        "campaign_registry",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_number", sa.Integer(), nullable=False, unique=True),
        sa.Column("campaign_code", sa.String(3), nullable=False, unique=True),
        sa.Column("campaign_public_id", sa.String(32), nullable=False, unique=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("vicidial_campaign_id", sa.String(8), nullable=False, unique=True),
        sa.Column("agent_group", sa.String(32), nullable=False, unique=True),
        sa.Column("dialplan_context", sa.String(80), nullable=False, unique=True),
        sa.Column(
            "parent_campaign_number",
            sa.Integer(),
            sa.ForeignKey("campaign_registry.campaign_number"),
        ),
        sa.Column(
            "extension_allocation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_extension_allocation.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "registry_status",
            sa.String(32),
            nullable=False,
            server_default="PROPOSED_DISABLED",
        ),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("source_change_id", sa.String(128), nullable=False),
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
            "campaign_number > 0 AND campaign_number % 100 = 0",
            name="ck_campaign_registry_number",
        ),
        sa.CheckConstraint(
            "campaign_code ~ '^[A-Z]{3}$'", name="ck_campaign_registry_code"
        ),
        sa.CheckConstraint(
            "campaign_public_id = 'CMP-' || campaign_number::text || '-' || campaign_code",
            name="ck_campaign_registry_public_id",
        ),
        sa.CheckConstraint(
            "registry_status IN ('PROPOSED_DISABLED','PROVISIONED_DISABLED','SECURITY_REVIEW','BUSINESS_APPROVAL','ACTIVATION_READY','ACTIVE','PAUSED','SUSPENDED','RETIRED')",
            name="ck_campaign_registry_status",
        ),
    )
    op.create_table(
        "campaign_object_identity",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_number",
            sa.Integer(),
            sa.ForeignKey("campaign_registry.campaign_number"),
            nullable=False,
        ),
        sa.Column("identity_type", sa.String(24), nullable=False),
        sa.Column("sequence_value", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.String(96), nullable=False, unique=True),
        sa.Column("full_alias", sa.String(112), nullable=True, unique=True),
        sa.Column("source_system", sa.String(32), nullable=False),
        sa.Column("source_object_id", sa.String(128), nullable=False),
        sa.Column(
            "identity_state",
            sa.String(24),
            nullable=False,
            server_default="ID_ASSIGNED",
        ),
        sa.Column(
            "dialing_state",
            sa.String(24),
            nullable=False,
            server_default="NOT_ELIGIBLE",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "campaign_number",
            "identity_type",
            "sequence_value",
            name="uq_campaign_object_identity_sequence",
        ),
        sa.UniqueConstraint(
            "source_system",
            "source_object_id",
            "identity_type",
            name="uq_campaign_object_identity_source",
        ),
        sa.CheckConstraint(
            "identity_state IN ('ID_ASSIGNED','VALIDATION_PENDING','VALIDATED','DUPLICATE_REVIEW','REJECTED','ARCHIVED')",
            name="ck_campaign_object_identity_state",
        ),
        sa.CheckConstraint(
            "dialing_state IN ('NOT_ELIGIBLE','ELIGIBILITY_PENDING','ELIGIBLE','ACTIVE','PAUSED','DO_NOT_CALL','CONSENT_REVOKED','CLOSED')",
            name="ck_campaign_object_dialing_state",
        ),
    )
    op.create_index(
        "ix_campaign_object_identity_campaign",
        "campaign_object_identity",
        ["campaign_number", "identity_type"],
    )
    op.create_table(
        "campaign_search_alias",
        sa.Column("alias", sa.String(160), primary_key=True),
        sa.Column(
            "campaign_number",
            sa.Integer(),
            sa.ForeignKey("campaign_registry.campaign_number"),
            nullable=False,
        ),
        sa.Column(
            "object_identity_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_object_identity.id"),
            nullable=True,
        ),
        sa.Column("alias_type", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_campaign_search_alias_scope",
        "campaign_search_alias",
        ["campaign_number", "alias"],
    )
    op.create_table(
        "campaign_feature_gate",
        sa.Column(
            "campaign_number",
            sa.Integer(),
            sa.ForeignKey("campaign_registry.campaign_number"),
            primary_key=True,
        ),
        sa.Column("feature_name", sa.String(48), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="DISABLED"),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('DISABLED','REVIEW','APPROVED','ACTIVE','PAUSED')",
            name="ck_campaign_feature_gate_status",
        ),
    )
    op.create_table(
        "campaign_activation_audit",
        sa.Column("activation_id", sa.String(64), primary_key=True),
        sa.Column(
            "campaign_number",
            sa.Integer(),
            sa.ForeignKey("campaign_registry.campaign_number"),
            nullable=False,
        ),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=False),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.execute(
        """
        CREATE FUNCTION campaign_identity_immutable() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'campaign identity history is immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'tr_campaign_identity_immutable';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in (
        "campaign_registry",
        "campaign_object_identity",
        "campaign_search_alias",
        "campaign_activation_audit",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION campaign_identity_immutable()"
        )
    op.execute(
        """
        CREATE TRIGGER trg_campaign_registry_identity_update
        BEFORE UPDATE OF campaign_number, campaign_code, campaign_public_id,
                         vicidial_campaign_id, extension_allocation_id
        ON campaign_registry
        FOR EACH ROW EXECUTE FUNCTION campaign_identity_immutable()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_campaign_object_identity_update
        BEFORE UPDATE OF campaign_number, identity_type, sequence_value,
                         public_id, full_alias, source_system, source_object_id
        ON campaign_object_identity
        FOR EACH ROW EXECUTE FUNCTION campaign_identity_immutable()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_campaign_search_alias_update
        BEFORE UPDATE ON campaign_search_alias
        FOR EACH ROW EXECUTE FUNCTION campaign_identity_immutable()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_campaign_activation_audit_update
        BEFORE UPDATE ON campaign_activation_audit
        FOR EACH ROW EXECUTE FUNCTION campaign_identity_immutable()
        """
    )


def downgrade():
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM campaign_registry)
             OR EXISTS (SELECT 1 FROM campaign_object_identity)
             OR EXISTS (SELECT 1 FROM campaign_activation_audit) THEN
            RAISE EXCEPTION 'downgrade would delete campaign identity history';
          END IF;
        END $$;
        """
    )
    for table in (
        "campaign_activation_audit",
        "campaign_search_alias",
        "campaign_object_identity",
        "campaign_registry",
    ):
        op.execute(f"DROP TRIGGER trg_{table}_no_delete ON {table}")
    op.execute(
        "DROP TRIGGER trg_campaign_activation_audit_update ON campaign_activation_audit"
    )
    op.execute("DROP TRIGGER trg_campaign_search_alias_update ON campaign_search_alias")
    op.execute(
        "DROP TRIGGER trg_campaign_object_identity_update ON campaign_object_identity"
    )
    op.execute(
        "DROP TRIGGER trg_campaign_registry_identity_update ON campaign_registry"
    )
    op.drop_table("campaign_activation_audit")
    op.drop_table("campaign_feature_gate")
    op.drop_index("ix_campaign_search_alias_scope", table_name="campaign_search_alias")
    op.drop_table("campaign_search_alias")
    op.drop_index(
        "ix_campaign_object_identity_campaign", table_name="campaign_object_identity"
    )
    op.drop_table("campaign_object_identity")
    op.drop_table("campaign_registry")
    op.execute("DROP FUNCTION campaign_identity_immutable()")
    op.execute("DROP SEQUENCE campaign_identity_global_seq")
