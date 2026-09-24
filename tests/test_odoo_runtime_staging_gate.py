from pathlib import Path

import pytest

from app.core.config import Settings


ROOT = Path(__file__).parents[1]


def test_odoo_runtime_gates_default_closed():
    settings = Settings()
    assert settings.odoo_read_enabled is False
    assert settings.odoo_sync_worker_enabled is False
    assert settings.odoo_result_delivery_enabled is False
    assert settings.odoo_staging_writes_enabled is False
    assert settings.odoo_production_writes_enabled is False
    assert settings.live_writes_enabled is False


def test_production_odoo_gate_is_rejected_by_global_safety_policy():
    settings = Settings(odoo_production_writes_enabled=True)
    with pytest.raises(ValueError, match="live writes"):
        settings.validate_safety()


def test_sync_worker_has_private_odoo_network_and_secret_file_mounts():
    compose = (ROOT / "deploy/compose.runtime.yaml").read_text()
    block = compose.split("middleware-sync-worker:", 1)[1].split(
        "middleware-notification-worker:", 1
    )[0]
    assert "codestra_internal_integration" in block
    assert "identity_service" in block
    assert "middleware_client_secret:/run/secrets/odoo_client_secret:ro" in block
    assert 'ODOO_PRODUCTION_WRITES_ENABLED: "false"' in block
    assert 'LIVE_WRITES_ENABLED: "false"' in block


def test_required_runtime_and_rollback_documents_exist():
    names = {
        "ODOO-MIDDLEWARE-ARCHITECTURE.md",
        "ODOO-RUNTIME-CONTRACT.md",
        "ODOO-OUTBOX-CONTRACT.md",
        "ODOO-RESULT-CONTRACT.md",
        "ODOO-FAILURE-RECOVERY.md",
        "ODOO-STAGING-RUNBOOK.md",
        "ODOO-PRODUCTION-ACTIVATION.md",
        "ODOO-ROLLBACK.md",
    }
    assert names == {path.name for path in (ROOT / "docs/odoo").iterdir()}
