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


def test_verified_child_tables_are_explicit_after_pas86_remediation():
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


def test_remediation_list_excludes_pas86_resolved_children():
    items = {record.table for record in remediation_list(validate_inventory(ROOT))}
    assert "agent_provisioning_step" not in items
    assert "agent_provisioning_audit" not in items
    assert "callback_delivery" not in items
    assert "callback_popup_ack" not in items
    assert "lead_automation_events" in items
