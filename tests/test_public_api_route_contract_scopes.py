from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_public_api_route_contract.py"
CONTRACT = ROOT / "deploy" / "public-api-route-contract.json"

EXPECTED = {
    ("GET", "/platform/v1/adapters"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/adapters/{adapter_id}"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/connectors"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/connectors/{connector_id}"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/dead-letters"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/dead-letters/{operation_id}"): ("platform-command-client", "platform.command.read"),
    ("POST", "/platform/v1/dead-letters/{operation_id}/replay"): ("platform-command-client", "platform.command.replay"),
    ("GET", "/platform/v1/reconciliation"): ("platform-command-client", "platform.command.read"),
    ("GET", "/platform/v1/reconciliation/{operation_id}"): ("platform-command-client", "platform.command.read"),
    ("POST", "/platform/v1/reconciliation/{operation_id}/readback"): ("platform-command-client", "platform.command.replay"),
    ("POST", "/platform/v1/reconciliation/{operation_id}/resolve"): ("platform-command-client", "platform.command.replay"),
}


def _generator():
    spec = importlib.util.spec_from_file_location("generate_public_api_route_contract", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_generator_classifies_command_kernel_operational_routes() -> None:
    module = _generator()
    for (method, path), expected in EXPECTED.items():
        assert module._platform_scope(path, method) == expected


def test_generated_contract_preserves_command_kernel_operational_scopes() -> None:
    document = json.loads(CONTRACT.read_text(encoding="utf-8"))
    rows = {(row["method"], row["path"]): row for row in document["routes"]}
    for key, (caller, scope) in EXPECTED.items():
        row = rows[key]
        assert row["calling_client"] == caller
        assert row["scope"] == scope
        assert row["audience"] == "middleware-api"
        assert row["auth"] == "service-or-user-jwt"
