"""Add immutable campaign extension blocks with overlap protection."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015_campaign_ext_allocation"
down_revision = "0014_telephony_call_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint(
        "ck_telephony_pool_end", "telephony_extension_pool", type_="check"
    )
    op.create_check_constraint(
        "ck_telephony_pool_end",
        "telephony_extension_pool",
        "range_end <= 9999",
    )
    op.create_table(
        "campaign_extension_allocation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", sa.String(64), nullable=False, unique=True),
        sa.Column("campaign_number", sa.Integer(), nullable=False, unique=True),
        sa.Column("allocation_public_id", sa.String(64), nullable=False, unique=True),
        sa.Column("extension_start", sa.Integer(), nullable=False),
        sa.Column("extension_end", sa.Integer(), nullable=False),
        sa.Column(
            "extension_range",
            postgresql.INT4RANGE(),
            sa.Computed(
                "int4range(extension_start, extension_end, '[]')",
                persisted=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "allocation_status",
            sa.String(24),
            nullable=False,
            server_default="PROPOSED",
        ),
        sa.Column("allocated_at", sa.DateTime(timezone=True)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("approved_by", sa.String(128)),
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
            "extension_start >= 6100",
            name="ck_campaign_extension_allocation_start",
        ),
        sa.CheckConstraint(
            "extension_end <= 9999",
            name="ck_campaign_extension_allocation_end",
        ),
        sa.CheckConstraint(
            "extension_start <= extension_end",
            name="ck_campaign_extension_allocation_order",
        ),
        sa.CheckConstraint(
            "campaign_number > 0 AND campaign_number % 100 = 0",
            name="ck_campaign_extension_allocation_number",
        ),
        sa.CheckConstraint(
            "allocation_status IN "
            "('PROPOSED','RESERVED_DISABLED','ACTIVE','PAUSED','RETIRED')",
            name="ck_campaign_extension_allocation_status",
        ),
        postgresql.ExcludeConstraint(
            ("extension_range", "&&"),
            using="gist",
            name="ex_campaign_extension_allocation_no_overlap",
        ),
    )
    op.execute("""
        CREATE FUNCTION protect_campaign_extension_allocation_identity()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'historical campaign extension allocations cannot be deleted'
              USING ERRCODE = 'integrity_constraint_violation',
                    CONSTRAINT = 'tr_campaign_extension_allocation_no_delete';
          END IF;
          IF NEW.campaign_id IS DISTINCT FROM OLD.campaign_id
             OR NEW.campaign_number IS DISTINCT FROM OLD.campaign_number
             OR NEW.allocation_public_id IS DISTINCT FROM OLD.allocation_public_id
             OR NEW.extension_start IS DISTINCT FROM OLD.extension_start
             OR NEW.extension_end IS DISTINCT FROM OLD.extension_end
             OR NEW.policy_hash IS DISTINCT FROM OLD.policy_hash
             OR NEW.source_change_id IS DISTINCT FROM OLD.source_change_id THEN
            RAISE EXCEPTION 'campaign extension allocation identity is immutable'
              USING ERRCODE = 'integrity_constraint_violation',
                    CONSTRAINT = 'tr_campaign_extension_allocation_immutable';
          END IF;
          RETURN NEW;
        END
        $$
    """)
    op.execute("""
        CREATE TRIGGER tr_campaign_extension_allocation_protect
        BEFORE UPDATE OR DELETE ON campaign_extension_allocation
        FOR EACH ROW EXECUTE FUNCTION protect_campaign_extension_allocation_identity()
    """)


def downgrade():
    connection = op.get_bind()
    above_old_ceiling = connection.execute(
        sa.text("SELECT count(*) FROM telephony_extension_pool WHERE range_end > 6999")
    ).scalar_one()
    if above_old_ceiling:
        raise RuntimeError("downgrade blocked: telephony extension pools exceed 6999")
    allocation_rows = connection.execute(
        sa.text("SELECT count(*) FROM campaign_extension_allocation")
    ).scalar_one()
    if allocation_rows:
        raise RuntimeError(
            "downgrade blocked: campaign extension allocation history exists"
        )
    op.drop_table("campaign_extension_allocation")
    op.execute("DROP FUNCTION protect_campaign_extension_allocation_identity()")
    op.drop_constraint(
        "ck_telephony_pool_end", "telephony_extension_pool", type_="check"
    )
    op.create_check_constraint(
        "ck_telephony_pool_end",
        "telephony_extension_pool",
        "range_end <= 6999",
    )
