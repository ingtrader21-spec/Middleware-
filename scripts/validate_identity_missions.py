#!/usr/bin/env python3
"""Validate executable mission schemas against source-only published contracts."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jsonschema import Draft202012Validator  # noqa: E402
from app.identity_missions import MISSION_COMMANDS, MISSION_RESULTS, READBACKS  # noqa: E402
from app.commands import CommandPolicyRegistry  # noqa: E402
from app.control_plane_auth import CONTROL_PLANE_CALLERS  # noqa: E402
from app.platform.safety import SafetySwitches  # noqa: E402


def validate() -> None:
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    spec = json.loads(
        (
            ROOT / "contracts/platform/identity-services-adapter.v1.openapi.json"
        ).read_text()
    )
    catalog = json.loads(
        (ROOT / "contracts/platform/identity-services.catalog.v1.json").read_text()
    )
    require(spec["x-mission-results"] == MISSION_RESULTS, "result schema drift")
    require(catalog["readback_contracts"] == READBACKS, "observability schema drift")
    policies = CommandPolicyRegistry.load()
    safety = SafetySwitches.load()
    branches = []

    def visit(node):
        if isinstance(node, dict):
            branches.extend(node.get("oneOf", []))
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(spec)
    for name, (capability, schema) in MISSION_COMMANDS.items():
        Draft202012Validator.check_schema(schema)
        matches = [
            v
            for v in branches
            if v.get("properties", {}).get("command_type", {}).get("const") == name
        ]
        require(
            len(matches) >= 2
            and all(v["properties"]["payload"] == schema for v in matches),
            f"{name}: command schema drift",
        )
        policy = policies.resolve(name)
        require(
            policy is not None and policy.capability == capability,
            f"{name}: policy drift",
        )
        require(
            policies.capabilities[capability] is False, f"{name}: activation forbidden"
        )
        require(
            "production" not in safety.gates[capability].environments,
            "production activation forbidden",
        )
        require(
            safety.provider_kill_switches[name.split(".")[0]],
            "provider activation forbidden",
        )
    for value in READBACKS.values():
        route = spec["paths"][value["path"] + "/{database_ref}"]
        require(set(route) == {"get"}, "observability must be GET-only")
        require(
            route["get"]["responses"]["200"]["content"]["application/json"]["schema"]
            == value["schema"],
            "readback drift",
        )
        Draft202012Validator.check_schema(value["schema"])
    matrix = json.loads(
        (ROOT / "contracts/platform/face-id-authorization.v1.json").read_text()
    )
    require(
        matrix["authority"] == "Keycloak" and matrix["state"] == "DECLARED_NOT_CREATED",
        "identity authority drift",
    )
    for client_id, profile in matrix["clients"].items():
        caller = CONTROL_PLANE_CALLERS[client_id]
        require(
            list(caller.allowed_command_prefixes)
            == profile["allowed_command_prefixes"],
            "caller prefix drift",
        )
        require(not profile["password_grant"], "password grants forbidden")
    routes = json.loads((ROOT / "connectors/generated/kong-routes.v1.json").read_text())
    require(
        not any(
            r["connector_id"] in catalog["source_reconciliation"]
            for r in routes["routes"]
        ),
        "private service ingress forbidden",
    )


if __name__ == "__main__":
    validate()
    print("IDENTITY_MISSIONS=PASS")
