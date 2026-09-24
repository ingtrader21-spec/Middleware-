"""Add monotonic-version and reconciliation read-back guards.

Revision ID: 0010_vicidial_registry_guards
Revises: 0009_vicidial_campaign_registry
"""

from alembic import op


revision = "0010_vicidial_registry_guards"
down_revision = "0009_vicidial_campaign_registry"
branch_labels = None
depends_on = None


def upgrade():
    op.create_check_constraint(
        "ck_vicidial_registry_reconciled_readback",
        "vicidial_campaign_registry",
        "drift_status <> 'reconciled' OR "
        "(last_read_back_at IS NOT NULL AND observed_state_hash IS NOT NULL)",
    )
    op.execute(
        """
        CREATE FUNCTION guard_vicidial_registry_version() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.mapping_version < OLD.mapping_version THEN
            RAISE EXCEPTION 'mapping version cannot decrease'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_vicidial_registry_version
        BEFORE UPDATE ON vicidial_campaign_registry
        FOR EACH ROW EXECUTE FUNCTION guard_vicidial_registry_version();
        """
    )


def downgrade():
    op.execute(
        "DROP TRIGGER trg_vicidial_registry_version ON vicidial_campaign_registry"
    )
    op.execute("DROP FUNCTION guard_vicidial_registry_version()")
    op.drop_constraint(
        "ck_vicidial_registry_reconciled_readback",
        "vicidial_campaign_registry",
        type_="check",
    )
