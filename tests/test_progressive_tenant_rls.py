from pathlib import Path

from app.platform.tenant_inventory import scan_tenant_inventory


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0069_progressive_tenant_rls.py"
CORE_SQL = ROOT / "migrations/0012_tenant_rls.sql"
AUTOMATION_SQL = ROOT / "migrations/automation/0002_tenant_rls.sql"


def _migration_namespace() -> dict[str, object]:
    namespace: dict[str, object] = {}
    exec(MIGRATION.read_text(encoding="utf-8"), namespace)
    return namespace


def _source_tables(prefix: str) -> set[str]:
    return {
        row.table
        for row in scan_tenant_inventory(ROOT)
        if row.ownership == "tenant_owned"
        and row.tenant_representation == "tenant_id_not_null"
        and row.source.startswith(prefix)
        and not row.table.startswith("callback_")
    }


def test_progressive_rls_coverage_is_partitioned_by_migration_authority() -> None:
    namespace = _migration_namespace()
    alembic = set(namespace["RLS_TABLES"])
    expected_alembic = _source_tables("migrations/versions/") - {
        "agent_provisioning_repair_intent",
        "agent_webrtc_session",
    }
    section6 = {"agent_provisioning_repair_intent", "agent_webrtc_session"}
    expected_core = (
        _source_tables("migrations/")
        - expected_alembic
        - section6
        - _source_tables("migrations/automation/")
    )
    expected_automation = _source_tables("migrations/automation/")

    assert alembic == expected_alembic
    core_sql = CORE_SQL.read_text(encoding="utf-8")
    automation_sql = AUTOMATION_SQL.read_text(encoding="utf-8")
    for table in expected_core:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in core_sql
        assert f"CREATE POLICY codestra_tenant_isolation ON {table}" in core_sql
    for table in expected_automation:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in automation_sql
        assert f"CREATE POLICY codestra_tenant_isolation ON {table}" in automation_sql


def test_rls_is_fail_closed_and_type_correct() -> None:
    namespace = _migration_namespace()
    source = MIGRATION.read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "current_setting('app.tenant_id', true)" in source
    assert "WITH CHECK" in source
    assert "FORCE ROW LEVEL SECURITY" not in source
    assert "migration/table owner retains" in source

    tenant_expression = namespace["_tenant_expression"]
    assert tenant_expression("social_accounts").endswith("::uuid")
    assert not tenant_expression("agent_provisioning_request").endswith("::uuid")


def test_sql_rls_migrations_are_forward_only_and_receipted() -> None:
    core = CORE_SQL.read_text(encoding="utf-8")
    automation = AUTOMATION_SQL.read_text(encoding="utf-8")
    assert "VALUES (12,'tenant_rls')" in core
    assert "VALUES (2,'tenant_rls')" in automation
    for text in (core, automation):
        assert "DISABLE ROW LEVEL SECURITY" not in text
        assert "BYPASSRLS" in text
        assert "WITH CHECK" in text


def test_section6_successor_owns_new_rls_tables() -> None:
    source = (ROOT / "migrations/versions/0070_agent_provisioning_lifecycle.py").read_text()
    for table in ("agent_provisioning_repair_intent", "agent_webrtc_session"):
        assert table in source
    assert 'for table in ("agent_provisioning_repair_intent", "agent_webrtc_session")' in source
    assert 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY' in source
    assert 'CREATE POLICY codestra_tenant_isolation ON {table}' in source
    assert "current_setting('app.tenant_id', true)" in source
