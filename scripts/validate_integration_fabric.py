#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path: str) -> dict:
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate() -> None:
    ownership = load("config/system-ownership.v2.json")
    capabilities = load("config/capabilities.v2.json")
    registry = load("config/adapter-registry.v2.json")
    command = load("contracts/platform/command-envelope.v1.schema.json")
    command_registry = load("connectors/generated/command-registry.v1.json")
    event = load("contracts/platform/event-envelope.v1.schema.json")
    event_alias = load("contracts/event-envelope.schema.json")
    catalog = load("contracts/platform/contract-catalog.v1.json")

    require(
        ownership["schema_version"] == "2.0",
        'integration fabric invariant failed: ownership["schema_version"] == "2.0"',
    )
    require(
        bool(ownership["systems"]["middleware"]["owns"]),
        'integration fabric invariant failed: ownership["systems"]["middleware"]["owns"]',
    )
    require(
        "direct_provider_write" in ownership["systems"]["n8n"]["forbidden"],
        'integration fabric invariant failed: "direct_provider_write" in ownership["systems"]["n8n"]["forbidden"]',
    )
    require(
        capabilities["default_policy"] == "DENY",
        'integration fabric invariant failed: capabilities["default_policy"] == "DENY"',
    )
    require(
        all(value is False for value in capabilities["capabilities"].values()),
        'integration fabric invariant failed: not any(capabilities["capabilities"].values())',
    )
    require(
        command_registry["default_policy"] == "DENY",
        'integration fabric invariant failed: command_registry["default_policy"] == "DENY"',
    )
    prefixes: set[str] = set()
    for policy in command_registry["commands"]:
        require(
            policy["prefix"] not in prefixes,
            'integration fabric invariant failed: policy["prefix"] not in prefixes',
        )
        prefixes.add(policy["prefix"])
        require(
            policy["required_capability"] in capabilities["capabilities"],
            'integration fabric invariant failed: policy["required_capability"] in capabilities["capabilities"]',
        )
        require(
            capabilities["capabilities"][policy["required_capability"]] is False,
            'integration fabric invariant failed: capabilities["capabilities"][policy["required_capability"]] is False',
        )
        require(
            policy["readback_required"] is True,
            'integration fabric invariant failed: policy["readback_required"] is True',
        )
        require(
            policy["unknown_outcome_requires_readback"] is True,
            'integration fabric invariant failed: policy["unknown_outcome_requires_readback"] is True',
        )

    adapter_prefixes: dict[str, set[str]] = {}
    for adapter in registry["adapters"]:
        adapter_id = adapter.get("id")
        require(
            isinstance(adapter_id, str) and bool(adapter_id),
            "integration fabric invariant failed: adapter ID is invalid",
        )
        require(
            adapter_id not in adapter_prefixes,
            'integration fabric invariant failed: adapter["id"] not in ids',
        )
        require(
            adapter["direct_n8n"] is False,
            'integration fabric invariant failed: adapter["direct_n8n"] is False',
        )
        command_prefixes = adapter.get("command_prefixes")
        require(
            isinstance(command_prefixes, list)
            and bool(command_prefixes)
            and all(
                isinstance(prefix, str) and bool(prefix)
                for prefix in command_prefixes
            )
            and len(command_prefixes) == len(set(command_prefixes)),
            'integration fabric invariant failed: adapter["command_prefixes"]',
        )
        adapter_prefixes[adapter_id] = set(command_prefixes)
        require(
            adapter["repository"].startswith("appolon1908-hue/"),
            'integration fabric invariant failed: adapter["repository"].startswith("appolon1908-hue/")',
        )

    for policy in command_registry["commands"]:
        connector_id = policy.get("connector_id")
        require(
            isinstance(connector_id, str) and connector_id in adapter_prefixes,
            "command references an unknown adapter: " + str(connector_id),
        )
        require(
            policy.get("prefix") in adapter_prefixes[connector_id],
            "command prefix is not declared by adapter: "
            + str(policy.get("prefix"))
            + " -> "
            + str(connector_id),
        )

    beyvra = next(
        adapter
        for adapter in registry["adapters"]
        if adapter["id"] == "beyvra-nonfinancial"
    )
    require(
        bool(beyvra["forbidden_prefixes"]),
        'integration fabric invariant failed: beyvra["forbidden_prefixes"]',
    )
    require(
        "wallet." in beyvra["forbidden_prefixes"],
        'integration fabric invariant failed: "wallet." in beyvra["forbidden_prefixes"]',
    )
    require(
        command["additionalProperties"] is False,
        'integration fabric invariant failed: command["additionalProperties"] is False',
    )
    require(
        event["additionalProperties"] is False,
        'integration fabric invariant failed: event["additionalProperties"] is False',
    )
    require(
        event_alias["$ref"]
        == ("https://contracts.codestra.co/platform/event-envelope.v1.schema.json"),
        'integration fabric invariant failed: event_alias["$ref"] == (',
    )
    require(
        catalog["canonical"]
        == {
            "event": "contracts/platform/event-envelope.v1.schema.json",
            "command": "contracts/platform/command-envelope.v1.schema.json",
            "api": "contracts/platform/integration-fabric-api.v2.yaml",
        },
        'integration fabric invariant failed: catalog["canonical"] == {',
    )
    require(
        all(
            projection["normalization_required"] is True
            for projection in catalog["wire_projections"]
        ),
        "integration fabric invariant failed: all(",
    )
    require(
        set(command["required"])
        == {
            "command_id",
            "command_type",
            "command_version",
            "target",
            "tenant_id",
            "requested_by",
            "correlation_id",
            "idempotency_key",
            "capability",
            "payload",
        },
        'integration fabric invariant failed: set(command["required"]) == {',
    )
    require(
        set(event["required"])
        == {
            "event_id",
            "event_type",
            "event_version",
            "occurred_at",
            "received_at",
            "source",
            "tenant_id",
            "correlation_id",
            "causation_id",
            "idempotency_key",
            "payload",
            "metadata",
        },
        'integration fabric invariant failed: set(event["required"]) == {',
    )


if __name__ == "__main__":
    validate()
    print("CODESTRA_INTEGRATION_FABRIC=PASS")
