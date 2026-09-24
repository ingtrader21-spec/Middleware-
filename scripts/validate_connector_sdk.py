#!/usr/bin/env python3
"""Validate Connector SDK manifests, standards, generated source, API, and storage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from middleware.connector_sdk import (  # noqa: E402
    ConnectorRegistry,
    ConnectorState,
)
from middleware.connector_sdk.errors import ConnectorError  # noqa: E402
from middleware.connector_sdk.generation import (  # noqa: E402
    build_generated_artifacts,
    render_generated_artifact,
)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    errors: list[str] = []
    manifest_dir = ROOT / "connectors" / "manifests"
    registry = ConnectorRegistry()
    try:
        records = registry.load_directory(
            manifest_dir,
            state=ConnectorState.DECLARED,
        )
    except (OSError, ValueError, ConnectorError) as error:
        errors.append(f"cannot load connector manifests: {error}")
        records = ()

    errors.extend(registry.validate_global_invariants())

    manifests_by_id = {
        record.manifest.connector_id: record.manifest for record in records
    }
    manifest_ids = set(manifests_by_id)
    adapter_registry_path = (
        ROOT / "config" / "adapter-registry.v2.json"
    )
    if adapter_registry_path.is_file():
        raw_adapter_registry = load_json(
            adapter_registry_path
        )
        if not isinstance(raw_adapter_registry, dict):
            errors.append(
                "config/adapter-registry.v2.json must be an object"
            )
        else:
            adapters = raw_adapter_registry.get("adapters")
            if not isinstance(adapters, list):
                errors.append(
                    "adapter registry adapters must be an array"
                )
            else:
                adapter_ids: set[str] = set()
                for item in adapters:
                    if not isinstance(item, dict):
                        errors.append("adapter registry entry must be an object")
                        continue
                    adapter_id = item.get("id")
                    if not isinstance(adapter_id, str) or not adapter_id:
                        errors.append("adapter registry ID must be a non-empty string")
                        continue
                    if adapter_id in adapter_ids:
                        errors.append(f"duplicate adapter registry ID: {adapter_id}")
                        continue
                    adapter_ids.add(adapter_id)

                    manifest = manifests_by_id.get(adapter_id)
                    if manifest is None:
                        continue
                    raw_prefixes = item.get("command_prefixes")
                    if not isinstance(raw_prefixes, list) or not all(
                        isinstance(prefix, str) and prefix
                        for prefix in raw_prefixes
                    ):
                        errors.append(
                            f"{adapter_id} adapter command prefixes are invalid"
                        )
                    else:
                        expected_prefixes = {
                            command.prefix for command in manifest.command_policies
                        }
                        observed_prefixes = set(raw_prefixes)
                        if (
                            len(observed_prefixes) != len(raw_prefixes)
                            or observed_prefixes != expected_prefixes
                        ):
                            errors.append(
                                f"{adapter_id} adapter command prefixes must exactly "
                                "match its connector manifest: "
                                f"manifest={sorted(expected_prefixes)} "
                                f"registry={sorted(observed_prefixes)}"
                            )
                    expected_sources = {
                        "cell": manifest.cell.value,
                        "repository": manifest.repository,
                    }
                    for field, expected in expected_sources.items():
                        if item.get(field) != expected:
                            errors.append(
                                f"{adapter_id} adapter {field} must match its "
                                f"connector manifest: manifest={expected!r} "
                                f"registry={item.get(field)!r}"
                            )
                if manifest_ids != adapter_ids:
                    errors.append(
                        "connector manifest IDs must exactly match "
                        "the v2 adapter registry: "
                        f"manifests={sorted(manifest_ids)} "
                        f"registry={sorted(str(value) for value in adapter_ids)}"
                    )

    capabilities: dict[str, bool] = {}
    for path in (
        ROOT / "config" / "capabilities.v2.json",
        ROOT / "connectors" / "capabilities.v1.json",
    ):
        raw = load_json(path)
        if not isinstance(raw, dict):
            errors.append(
                f"{path.relative_to(ROOT)} must be an object"
            )
            continue
        values = raw.get("capabilities")
        if not isinstance(values, dict):
            errors.append(
                f"{path.relative_to(ROOT)} capabilities "
                "must be an object"
            )
            continue
        for key, value in values.items():
            if not isinstance(key, str) or not isinstance(
                value,
                bool,
            ):
                errors.append(
                    f"{path.relative_to(ROOT)} has invalid "
                    f"capability {key!r}"
                )
                continue
            if value is not False:
                errors.append(
                    "source capability must remain false: "
                    f"{key}={value}"
                )
            capabilities[key] = value

    for record in records:
        manifest = record.manifest
        if (
            manifest.enabled_by_default
            or manifest.direct_n8n_access
        ):
            errors.append(
                f"{manifest.connector_id} violates "
                "disabled/Middleware-only policy"
            )
        if (
            manifest.runtime_binding.status
            != "UNVERIFIED_TEMPLATE_ONLY"
        ):
            errors.append(
                f"{manifest.connector_id} runtime binding "
                "is not source-only"
            )
        if not manifest.runtime_binding.base_url.endswith(
            ".internal.invalid"
        ):
            errors.append(
                f"{manifest.connector_id} source base URL "
                "is not reserved .invalid"
            )
        for command in manifest.command_policies:
            if (
                command.required_capability != "NONE"
                and command.required_capability
                not in capabilities
            ):
                errors.append(
                    f"{manifest.connector_id} references "
                    "unknown capability "
                    f"{command.required_capability}"
                )
        for webhook in manifest.webhook_policies:
            if webhook.replay_retention_seconds < 604800:
                errors.append(
                    f"{manifest.connector_id} webhook replay "
                    "retention is below seven days"
                )

    expected_generated = build_generated_artifacts(
        manifest_dir
    )
    for name, data in expected_generated.items():
        path = ROOT / "connectors" / "generated" / name
        if not path.is_file():
            errors.append(
                f"missing generated artifact: "
                f"{path.relative_to(ROOT)}"
            )
        elif path.read_text(
            encoding="utf-8"
        ) != render_generated_artifact(data):
            errors.append(
                f"stale generated artifact: "
                f"{path.relative_to(ROOT)}"
            )

    manifest_schema = load_json(
        ROOT
        / "contracts"
        / "connectors"
        / "connector-manifest.v1.schema.json"
    )
    if (
        not isinstance(manifest_schema, dict)
        or manifest_schema.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
    ):
        errors.append(
            "connector manifest JSON Schema is missing or invalid"
        )

    cloud_schema = load_json(
        ROOT
        / "contracts"
        / "connectors"
        / "cloudevent.v1.schema.json"
    )
    if (
        not isinstance(cloud_schema, dict)
        or cloud_schema.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or cloud_schema.get("properties", {})
        .get("specversion", {})
        .get("const")
        != "1.0"
    ):
        errors.append(
            "CloudEvents 1.0 JSON Schema is missing or invalid"
        )

    storage_text = (
        ROOT
        / "contracts"
        / "connectors"
        / "connector-storage.v1.sql"
    ).read_text(encoding="utf-8")
    for marker in (
        "connector_manifests",
        "connector_installations",
        "connector_connections",
        "connector_webhook_endpoints",
        "connector_webhook_event_keys",
        "connector_webhook_inbox",
        "connector_operations",
        "connector_outbox",
        "UNIQUE (connector_id, version, manifest_digest)",
        "connector_webhook_event_keys_tenant_policy",
        "tenant_resolution",
        "cloud_event jsonb",
        "FORCE ROW LEVEL SECURITY",
    ):
        if marker not in storage_text:
            errors.append(
                f"connector storage contract is missing {marker}"
            )
    if "UNIQUE (route_path)" in storage_text:
        errors.append(
            "webhook route_path cannot be globally unique "
            "across tenant connections"
        )

    api_text = (
        ROOT
        / "contracts"
        / "connectors"
        / "connector-management-api.v1.yaml"
    ).read_text(encoding="utf-8")
    for marker in (
        "openapi: 3.1.1",
        "jsonSchemaDialect: "
        "https://json-schema.org/draft/2020-12/schema",
        "/v1/connectors/validate:",
        "/v1/connectors/install:",
        "/v1/connectors/{connector_id}/upgrade:",
        "/v1/webhooks/{webhook_id}/rotate-secret:",
        "/v1/webhook-deliveries/{delivery_id}/replay-request:",
        "/v1/webhooks/{connector_id}/{endpoint_key}:",
        "application/problem+json:",
        "traceparent",
        "tracestate",
        "./connector-manifest.v1.schema.json",
        "./cloudevent.v1.schema.json",
    ):
        if marker not in api_text:
            errors.append(
                f"connector API is missing {marker}"
            )

    standards_path = (
        ROOT
        / "docs"
        / "connectors"
        / "CONNECTOR_SDK_STANDARDS_PROFILE_V1.md"
    )
    if not standards_path.is_file():
        errors.append(
            "connector standards compatibility profile is missing"
        )
    else:
        standards_text = standards_path.read_text(
            encoding="utf-8"
        )
        for marker in (
            "OpenAPI 3.1.1",
            "JSON Schema Draft 2020-12",
            "CloudEvents 1.0",
            "W3C Trace Context",
            "RFC 9457",
            "RFC 9700",
            "Semantic Versioning 2.0.0",
        ):
            if marker not in standards_text:
                errors.append(
                    "standards profile is missing " + marker
                )

    if errors:
        print(
            "CONNECTOR_SDK_VALIDATION=FAIL",
            file=sys.stderr,
        )
        for validation_error in errors:
            print(f"ERROR={validation_error}", file=sys.stderr)
        return 1

    print(
        "CONNECTOR_SDK_VALIDATION=PASS "
        f"CONNECTORS={len(records)} "
        f"CAPABILITIES={len(capabilities)} "
        "STANDARDS_PROFILE=PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
