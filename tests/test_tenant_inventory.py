from pathlib import Path

from app.platform.tenant_inventory import (
    INVENTORY_RELATIVE_PATH,
    inventory_by_table,
    inventory_document,
    load_inventory_snapshot,
    remediation_list,
    scan_tenant_inventory,
    validate_inventory,
    validate_snapshot_matches_migrations,
    write_inventory_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_minimal_core_inventory_fixture(root: Path) -> Path:
    (root / "migrations").mkdir(parents=True)
    (root / "config").mkdir()
    migration = root / "migrations" / "0001.sql"
    migration.write_text(
        "\n".join(
            [
                "CREATE TABLE middleware_commands (tenant_id text NOT NULL, command_id text);",
                "CREATE TABLE middleware_command_attempts (tenant_id text NOT NULL, id bigint);",
                "CREATE TABLE middleware_command_audit (tenant_id text NOT NULL, id bigint);",
                "CREATE TABLE middleware_inbox (tenant_id text NOT NULL, event_id text);",
                "CREATE TABLE middleware_outbox (tenant_id text NOT NULL, id bigint);",
                "CREATE TABLE middleware_event_ledger (tenant_id text NOT NULL, id bigint);",
                "CREATE TABLE middleware_reconciliation_audit (tenant_id text NOT NULL, id bigint);",
            ]
        )
        + "\n"
    )
    return migration


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


def test_reviewed_snapshot_matches_current_migrations_exactly():
    records = validate_inventory(ROOT)
    snapshot = load_inventory_snapshot(ROOT)
    assert snapshot == records
    assert inventory_document(records)["tables"]


def test_programmatic_inventory_handoff_is_stable():
    records = inventory_by_table(ROOT)
    assert records["middleware_commands"].ownership == "tenant_owned"
    assert records["callback_delivery"].ownership == "tenant_owned_inherited"
    assert records["middleware_schema_migrations"].ownership == "global"


def test_new_durable_table_requires_explicit_snapshot_review(tmp_path):
    migration = _write_minimal_core_inventory_fixture(tmp_path)
    write_inventory_snapshot(tmp_path)

    migration.write_text(
        migration.read_text()
        + "CREATE TABLE brand_new_durable_table (id bigint PRIMARY KEY);\n"
    )
    try:
        validate_inventory(tmp_path)
    except ValueError as exc:
        assert "new tables=brand_new_durable_table" in str(exc)
    else:
        raise AssertionError("new durable table must require snapshot review")

def test_removed_or_reclassified_table_requires_snapshot_review(tmp_path):
    migration = _write_minimal_core_inventory_fixture(tmp_path)
    write_inventory_snapshot(tmp_path)

    migration.write_text(
        migration.read_text().replace(
            "middleware_commands (tenant_id text NOT NULL",
            "middleware_commands (tenant_id text",
        )
    )
    try:
        validate_inventory(tmp_path)
    except ValueError as exc:
        assert (
            "tenant-owned table is not fail-closed" in str(exc)
            or "reclassified tables=middleware_commands" in str(exc)
        )
    else:
        raise AssertionError("tenant representation drift must fail closed")

def test_snapshot_schema_rejects_duplicate_entries(tmp_path):
    _write_minimal_core_inventory_fixture(tmp_path)
    path = write_inventory_snapshot(tmp_path)
    import json

    payload = json.loads(path.read_text())
    payload["tables"].append(dict(payload["tables"][0]))
    path.write_text(json.dumps(payload))
    try:
        load_inventory_snapshot(tmp_path)
    except ValueError as exc:
        assert "duplicate table" in str(exc)
    else:
        raise AssertionError("duplicate reviewed inventory row must fail")
