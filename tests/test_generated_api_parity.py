from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from app.main import create_app
from scripts.generate_api_contracts import (
    HTTP_METHODS,
    MUTATION_METHODS,
    REQUIRED_HEADERS,
    SPECIALIZED_INGRESS_PATHS,
    _ensure_header,
    _klyrow_contract_documents,
    _normalize_schema_defaults,
    build_documents,
    render_documents,
)


def _routes(paths: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in paths.items()
        for method in item
        if method in HTTP_METHODS
    }


def _load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_yaml(path: str) -> dict[str, Any]:
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_generated_openapi_contract_and_matrix_match_runtime(test_settings) -> None:
    runtime = create_app(settings=test_settings).openapi()
    generated = _load_json("contracts/platform/middleware-openapi.generated.json")
    contract = _load_yaml("contracts/platform/integration-fabric-api.v2.yaml")
    matrix = _load_yaml("config/api-completion-matrix.yaml")
    expected = _routes(runtime["paths"])
    assert expected == _routes(generated["paths"]) == _routes(contract["paths"])
    assert expected == {
        (row["method"], row["path"]) for row in matrix["operations"]
    }
    assert matrix["classification_complete"] is True
    assert matrix["unknown_endpoints"] == 0
    assert not {"MISSING", "PARTIAL", "UNKNOWN"} & {
        row["runtime_state"] for row in matrix["operations"]
    }
    assert generated["components"]["securitySchemes"]["bearerAuth"]["scheme"] == (
        "bearer"
    )


def test_committed_contract_artifacts_exactly_match_the_generator() -> None:
    schema, matrix = build_documents()
    for path, expected in render_documents(schema, matrix).items():
        assert path.read_text(encoding="utf-8") == expected


def test_generated_contract_documents_each_required_header_once() -> None:
    contract = _load_yaml("contracts/platform/integration-fabric-api.v2.yaml")
    for path, item in contract["paths"].items():
        if not path.startswith(("/v1/", "/api/v1/")):
            continue
        if path == "/v1/runtime/safety" or "webhook" in path:
            continue
        if path in SPECIALIZED_INGRESS_PATHS:
            continue
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            header_names = [
                parameter["name"].casefold()
                for parameter in operation.get("parameters", [])
                if parameter.get("in") == "header"
            ]
            required = {"x-tenant-id"}
            if method in MUTATION_METHODS:
                required |= {"x-correlation-id", "idempotency-key"}
            for name in required:
                assert header_names.count(name) == 1, (path, method, name)


def test_generator_adds_each_mutation_header_independently() -> None:
    parameters = [deepcopy(REQUIRED_HEADERS["X-Correlation-ID"])]
    _ensure_header(parameters, "X-Correlation-ID")
    _ensure_header(parameters, "Idempotency-Key")
    assert [parameter["name"] for parameter in parameters] == [
        "X-Correlation-ID",
        "Idempotency-Key",
    ]


def test_generator_rejects_weaker_existing_header_contract() -> None:
    weak_tenant = deepcopy(REQUIRED_HEADERS["X-Tenant-ID"])
    weak_tenant["required"] = False
    with pytest.raises(ValueError, match="non-canonical X-Tenant-ID"):
        _ensure_header([weak_tenant], "X-Tenant-ID")


def test_generator_normalizes_only_redundant_open_object_defaults() -> None:
    schema = {
        "open": {"type": "object", "additionalProperties": True},
        "closed": {"type": "object", "additionalProperties": False},
        "nested": [{"additionalProperties": {"type": "string"}}],
    }
    _normalize_schema_defaults(schema)
    assert schema == {
        "open": {"type": "object"},
        "closed": {"type": "object", "additionalProperties": False},
        "nested": [{"additionalProperties": {"type": "string"}}],
    }


def test_generated_klyrow_contracts_normalize_open_object_defaults() -> None:
    for rendered in _klyrow_contract_documents().values():
        assert '"additionalProperties": true' not in rendered


def test_generated_contract_documents_mutation_headers() -> None:
    contract = _load_yaml("contracts/platform/integration-fabric-api.v2.yaml")
    operations = (
        ("/v1/inbox/{record_id}/quarantine", "post"),
        ("/v1/outbox/{record_id}/cancel", "post"),
        ("/v1/operations/{command_id}/cancel", "post"),
        ("/v1/intake/leads", "post"),
        ("/v1/intake/surveys/responses", "post"),
    )
    for path, method in operations:
        names = {
            item["name"] for item in contract["paths"][path][method]["parameters"]
        }
        assert {"X-Tenant-ID", "X-Correlation-ID", "Idempotency-Key"} <= names


def test_communication_success_responses_use_typed_schemas(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    expected = {
        ("/v1/communication/messages", "post", "CommunicationMessage"),
        ("/v1/communications/messages", "post", "CommunicationMessage"),
        ("/v1/communications/messages", "get", "CommunicationMessagePage"),
        ("/v1/communications/messages/{messageId}", "get", "CommunicationMessage"),
        (
            "/v1/communications/messages/{messageId}/events",
            "get",
            "CommunicationEventPage",
        ),
        (
            "/v1/communications/messages/{messageId}/cancel",
            "post",
            "CommunicationMessage",
        ),
        (
            "/v1/communications/providers/health",
            "get",
            "ProviderHealthReport",
        ),
        (
            "/v1/communications/reputation",
            "get",
            "ProviderReputationReport",
        ),
        ("/v1/communications/usage", "get", "CommunicationUsageReport"),
    }
    for path, method, model in expected:
        response = schema["paths"][path][method]["responses"]["200"]
        assert response["content"]["application/json"]["schema"] == {
            "$ref": f"#/components/schemas/{model}"
        }


def test_communication_usage_query_timestamps_are_validated(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    parameters = schema["paths"]["/v1/communications/usage"]["get"]["parameters"]
    timestamps = {
        item["name"]: item["schema"]
        for item in parameters
        if item["name"] in {"from", "to"}
    }
    expected_timestamp = {
        "anyOf": [
            {"format": "date-time", "type": "string"},
            {"type": "null"},
        ],
    }
    assert timestamps == {
        "from": {**expected_timestamp, "title": "From"},
        "to": {**expected_timestamp, "title": "To"},
    }
    responses = schema["paths"]["/v1/communications/usage"]["get"]["responses"]
    assert "422" not in responses
    assert responses["400"]["content"]["application/json"]["schema"]["required"] == [
        "error"
    ]


def test_webhook_business_422_responses_remain_documented(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    webhook_operations = [
        operation
        for item in schema["paths"].values()
        for method, operation in item.items()
        if method == "post"
        and (
            str(operation.get("operationId", "")).startswith("ingress_")
            or "webhook" in str(operation.get("operationId", ""))
            or str(operation.get("operationId", "")).startswith("crm_event_")
        )
    ]
    assert webhook_operations
    for operation in webhook_operations:
        response = operation["responses"]["422"]
        assert response["description"] == (
            "Event type is not allowed for this webhook"
        )
        assert response["content"]["application/json"]["schema"]["required"] == [
            "error"
        ]
