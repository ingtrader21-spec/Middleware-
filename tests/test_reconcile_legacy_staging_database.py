from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_legacy_staging_database.py"


def _load():
    spec = spec_from_file_location("legacy_db_reconcile", SCRIPT)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reconciliation_contract_is_pinned_to_exact_lineages():
    module = _load()
    assert module.LEGACY_SOURCE_SHA == "b29db772ed82c0d2f1adfdb8e6da58d4baa77524"
    assert module.LEGACY_HEAD == "0058_odoo_delivery_sources"
    assert module.SHARED_HEAD == "0056_klyrow_delivery_events"
    assert module.TARGET_HEAD == "0069_agent_provisioning_rls"
    assert module.LEGACY_ENDPOINT_ID == "55000000-0000-4000-8000-000000000021"
    assert module.CANONICAL_ENDPOINT_ID == "66000000-0000-4000-8000-000000000012"


def test_reconciliation_is_staging_only_and_preserves_business_ledgers():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'database != "middleware_staging"' in source
    assert '"odoo_result_delivery"' in source
    assert '"integration_event"' in source
    assert '"outbox_event"' in source
    assert "preserved business row counts changed" in source
    assert "pg_advisory_xact_lock" in source
    assert 'parser.add_argument("--execute", action="store_true")' in source
    assert 'raise ReconcileError("--execute is required")' in source


def test_reconciliation_deletes_only_legacy_registry_metadata():
    source = SCRIPT.read_text(encoding="utf-8").lower()
    destructive = [
        line.strip()
        for line in source.splitlines()
        if "delete from" in line
    ]
    assert destructive
    assert all(
        any(
            table in line
            for table in (
                "integration_route_binding",
                "integration_endpoint_version",
                "integration_schema_version",
                "integration_endpoint",
            )
        )
        for line in destructive
    )
    assert "delete from odoo_result_delivery" not in source
    assert "delete from integration_event" not in source
    assert "delete from outbox_event" not in source
