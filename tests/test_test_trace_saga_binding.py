import ast
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.telephony import ProvisionRequest, validate_trace_binding


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/versions/0022_test_trace_binding.py"


def request(**overrides):
    values = {
        "request_id": "CTR-20260729T040200Z-0002-PROVISION",
        "employee_id": "400-AGT-90000001",
        "business_unit": "BU-400-COD",
        "campaign": "CMP-400-COD",
        "role": "TEST_AGENT",
        "idempotency_key": "CTR-20260729T040200Z-0002:agent.provision",
        "approved_odoo_request": True,
        "record_environment": "TEST",
        "test_run_id": "CTR-20260729T040200Z-0002",
        "causation_id": "ODOO-OUTBOX-CTR-0002",
        "policy_hash": "a" * 64,
    }
    values.update(overrides)
    return ProvisionRequest(**values)


def test_controlled_test_request_carries_complete_trace_binding():
    value = request()
    validate_trace_binding(value)
    assert value.record_environment == "TEST"
    assert value.test_run_id == "CTR-20260729T040200Z-0002"
    assert value.causation_id == "ODOO-OUTBOX-CTR-0002"
    assert value.policy_hash == "a" * 64


@pytest.mark.parametrize(
    "override",
    [
        {"policy_hash": "not-a-hash"},
        {"record_environment": "UNTRUSTED"},
    ],
)
def test_trace_binding_schema_fails_closed(override):
    with pytest.raises(ValidationError):
        request(**override)


@pytest.mark.parametrize(
    "override",
    [
        {"test_run_id": None},
        {"causation_id": None},
        {"policy_hash": None},
        {"business_unit": "BU-OTHER"},
        {"campaign": "CMP-OTHER"},
        {
            "record_environment": "PRODUCTION",
            "test_run_id": "CTR-PROHIBITED",
        },
    ],
)
def test_trace_binding_policy_fails_closed(override):
    with pytest.raises(HTTPException) as exc:
        validate_trace_binding(request(**override))
    assert exc.value.status_code == 422


def test_migration_extends_existing_saga_without_a_reaction_table():
    source = MIGRATION.read_text(encoding="utf-8")
    assert "telephony_provisioning_saga" in source
    assert "test_run_id" in source
    assert "causation_id" in source
    assert "policy_hash" in source
    assert "create_table" not in source
    assert "reaction" not in source.lower()


def test_migration_chain_and_revision_width():
    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    values = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"revision", "down_revision"}
    }
    assert values == {
        "revision": "0022_test_trace_binding",
        "down_revision": "0021_async_comm_contract",
    }
    assert len(values["revision"]) <= 32
