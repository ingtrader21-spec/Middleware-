from pathlib import Path

from app.platform.tenant_inventory import (
    remediation_list,
    scan_tenant_inventory,
    validate_inventory,
)


ROOT = Path(__file__).resolve().parents[1]


def test_inventory_covers_current_durable_migrations_without_duplicates():
    records = validate_inventory(ROOT)
    names = [record.table for record in records]
    assert len(names) == len(set(names))
    assert len(records) >= 90


def test_core_v3_tables_are_explicit_tenant_owned():
    records = {record.table: record for record in scan_tenant_inventory(ROOT)}
    for table in (
        "middleware_commands",
        "middleware_command_attempts",
        "middleware_command_audit",
        "middleware_inbox",
        "middleware_outbox",
        "middleware_event_ledger",
        "middleware_reconciliation_audit",
        "middleware_automation_jobs",
        "middleware_communication_messages",
    ):
        record = records[table]
        assert record.ownership == "tenant_owned"
        assert record.tenant_representation == "tenant_id_not_null"


def test_verified_child_tables_are_classified_as_inherited_not_global():
    records = {record.table: record for record in scan_tenant_inventory(ROOT)}
    expected = {
        "agent_provisioning_step": "agent_provisioning_request",
        "agent_provisioning_audit": "agent_provisioning_request",
        "callback_delivery": "callback_record",
        "callback_popup_ack": "callback_record",
    }
    for table, parent in expected.items():
        record = records[table]
        assert record.ownership == "tenant_owned_inherited"
        assert record.parent_table == parent
        assert record.remediation


def test_schema_migration_tables_are_global_metadata():
    records = {record.table: record for record in scan_tenant_inventory(ROOT)}
    assert records["middleware_schema_migrations"].ownership == "global"
    assert records["middleware_automation_schema_migrations"].ownership == "global"


def test_unclassified_feature_tables_fail_closed_to_review_required():
    records = {record.table: record for record in scan_tenant_inventory(ROOT)}
    for table in (
        "lead_automation_events",
        "recordings",
        "social_content_job",
        "platform_services",
        "website_submission",
    ):
        assert records[table].ownership == "review_required"
        assert records[table].tenant_representation == "none_explicit"


def test_remediation_list_includes_inherited_and_unclassified_tables():
    items = {record.table for record in remediation_list(validate_inventory(ROOT))}
    assert "agent_provisioning_step" in items
    assert "callback_delivery" in items
    assert "lead_automation_events" in items
