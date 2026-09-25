from pathlib import Path

from app.platform.tenant_inventory import scan_tenant_inventory


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0069_progressive_tenant_rls.py"


def test_progressive_rls_covers_canonical_non_callback_tenant_tables() -> None:
    namespace: dict[str, object] = {}
    exec(MIGRATION.read_text(encoding="utf-8"), namespace)
    configured = set(namespace["RLS_TABLES"])
    inventory = scan_tenant_inventory(ROOT)
    expected = {
        row.table
        for row in inventory
        if row.ownership == "tenant_owned"
        and row.tenant_representation == "tenant_id_not_null"
        and not row.table.startswith("callback_")
    }
    assert configured == expected


def test_rls_is_fail_closed_and_maintenance_owner_behavior_is_explicit() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "current_setting('app.tenant_id', true)" in source
    assert "WITH CHECK" in source
    assert "FORCE ROW LEVEL SECURITY" not in source
    assert "migration/table owner retains" in source
