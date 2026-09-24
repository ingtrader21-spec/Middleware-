from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "versions"
    / "0047_breero_runtime_grants.py"
)


def test_breero_runtime_grants_follow_current_head() -> None:
    source = MIGRATION.read_text()

    assert 'revision = "0047_breero_runtime_grants"' in source
    assert 'down_revision = "0046_breero_complete_envelope"' in source


def test_breero_runtime_grants_are_least_privilege() -> None:
    source = MIGRATION.read_text()

    assert 'RUNTIME_ROLE = "mw_integration_api"' in source
    assert '"breero_event_receipt": "SELECT, INSERT, UPDATE"' in source
    assert '"breero_odoo_outbox": "SELECT, INSERT, UPDATE"' in source
    assert '"breero_replay_nonce": "SELECT, INSERT"' in source
    assert '"breero_integration_audit": "INSERT"' in source
    assert "breero_integration_audit_id_seq" in source
    assert "DELETE" not in source
    assert "CREATE ROLE" not in source
    assert "ALTER ROLE" not in source
    assert "GRANT ALL" not in source
