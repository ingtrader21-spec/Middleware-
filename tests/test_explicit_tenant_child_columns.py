from pathlib import Path

from app.db.models import (
    AgentProvisioningAudit,
    AgentProvisioningStep,
    CallbackDelivery,
)
from app.platform.tenant_inventory import scan_tenant_inventory


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0068_explicit_tenant_child_columns.py"


def test_pas86_extends_single_alembic_head():
    source = MIGRATION.read_text()
    assert 'revision = "0068_explicit_tenant_child_columns"' in source
    assert 'down_revision = "0067_service_catalog_monitoring_state"' in source


def test_inherited_tenant_children_become_explicit_not_null():
    source = MIGRATION.read_text()
    for table in (
        "agent_provisioning_step",
        "agent_provisioning_audit",
        "callback_delivery",
        "callback_popup_ack",
    ):
        assert f"ALTER TABLE {table} ADD COLUMN tenant_id" in source
        assert f"ALTER TABLE {table} ALTER COLUMN tenant_id SET NOT NULL" in source


def test_tenant_matching_parent_constraints_are_present():
    source = MIGRATION.read_text()
    for constraint in (
        "fk_agent_provisioning_step_tenant_request",
        "fk_agent_provisioning_audit_tenant_request",
        "fk_callback_delivery_tenant_callback",
        "fk_callback_popup_ack_tenant_callback",
    ):
        assert constraint in source


def test_callback_child_rls_uses_direct_transaction_tenant():
    source = MIGRATION.read_text()
    assert "CREATE POLICY callback_delivery_tenant ON callback_delivery" in source
    assert "CREATE POLICY callback_popup_ack_tenant ON callback_popup_ack" in source
    assert "current_setting('app.tenant_id', true)" in source


def test_orm_models_expose_explicit_tenant_id():
    assert "tenant_id" in CallbackDelivery.__table__.columns
    assert CallbackDelivery.__table__.columns["tenant_id"].nullable is False
    assert "tenant_id" in AgentProvisioningStep.__table__.columns
    assert AgentProvisioningStep.__table__.columns["tenant_id"].nullable is False
    assert "tenant_id" in AgentProvisioningAudit.__table__.columns
    assert AgentProvisioningAudit.__table__.columns["tenant_id"].nullable is False


def test_pas85_inventory_consumes_later_explicit_tenant_remediation():
    records = {record.table: record for record in scan_tenant_inventory(ROOT)}
    for table in (
        "agent_provisioning_step",
        "agent_provisioning_audit",
        "callback_delivery",
        "callback_popup_ack",
    ):
        record = records[table]
        assert record.ownership == "tenant_owned"
        assert record.tenant_representation == "tenant_id_not_null"
        assert record.remediation is None
