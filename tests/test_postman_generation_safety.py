from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_postman.py"
SPEC = importlib.util.spec_from_file_location("middleware_postman_generator", MODULE_PATH)
assert SPEC and SPEC.loader
postman = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = postman
SPEC.loader.exec_module(postman)


def _flatten(collection: dict) -> list[dict]:
    return [
        request
        for group in collection["item"]
        for request in group.get("item", [])
    ]


def test_generated_collection_has_fail_closed_effect_guard() -> None:
    collection, _ = postman.build()
    prerequest = next(
        event for event in collection["event"] if event["listen"] == "prerequest"
    )
    script = "\n".join(prerequest["script"]["exec"])
    assert "RUN_EFFECTFUL" in script
    assert "environment" in script
    assert "production" in script
    assert "pm.execution.skipRequest()" in script
    values = {row["key"]: row["value"] for row in collection["variable"]}
    assert values["RUN_EFFECTFUL"] == "false"
    assert values["environment"] == "local"


def test_generated_requests_assert_openapi_success_statuses() -> None:
    collection, _ = postman.build()
    requests = _flatten(collection)
    assert requests
    for request in requests:
        test_event = next(
            event for event in request["event"] if event["listen"] == "test"
        )
        script = "\n".join(test_event["script"]["exec"])
        assert "allowedSuccessStatuses" in script
        assert "response matches OpenAPI success contract" in script


def test_generated_collection_keeps_response_correlation_assertion() -> None:
    collection, _ = postman.build()
    test_event = next(
        event for event in collection["event"] if event["listen"] == "test"
    )
    script = "\n".join(test_event["script"]["exec"])
    assert "X-Request-ID" in script
    assert "X-Correlation-ID" in script


def test_generated_collection_defaults_to_loopback_and_empty_tokens() -> None:
    collection, _ = postman.build()
    values = {row["key"]: row["value"] for row in collection["variable"]}
    assert values["base_url"] == "http://127.0.0.1:8095"
    assert values["bearer_token"] == ""
    assert values["db_read_token"] == ""
    assert values["db_verify_token"] == ""


def test_path_and_path_item_parameters_render_as_postman_variables() -> None:
    doc = {}
    path_item = {
        "parameters": [
            {
                "name": "request_id",
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
        ]
    }
    op = {
        "parameters": [
            {
                "name": "activity_id",
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
        ],
        "responses": {"200": {"description": "ok"}},
    }
    item = postman._request(
        doc,
        "/platform/v1/requests/{request_id}/activities/{activity_id}",
        "get",
        path_item,
        op,
    )
    raw = item["request"]["url"]["raw"]
    assert "{request_id}" not in raw.replace("{{request_id}}", "")
    assert "{activity_id}" not in raw.replace("{{activity_id}}", "")
    assert "{{request_id}}" in raw
    assert "{{activity_id}}" in raw


def test_operation_parameter_overrides_path_item_parameter() -> None:
    doc = {}
    path_item = {
        "parameters": [
            {"name": "X-Tenant", "in": "header", "required": False}
        ]
    }
    op = {
        "parameters": [
            {"name": "X-Tenant", "in": "header", "required": True}
        ],
        "responses": {"200": {"description": "ok"}},
    }
    params = postman._parameters(doc, path_item, op)
    assert len(params) == 1
    assert params[0]["required"] is True


def test_expected_statuses_prefer_success_and_health_is_exact_200() -> None:
    op = {
        "responses": {
            "200": {"description": "ok"},
            "202": {"description": "accepted"},
            "400": {"description": "bad request"},
            "default": {"description": "fallback"},
        }
    }
    assert postman._expected_statuses(op, "/platform/v1/example") == [200, 202]
    assert postman._expected_statuses(op, "/readyz") == [200]


def test_expected_statuses_preserve_explicit_negative_only_contract() -> None:
    op = {
        "responses": {
            "400": {"description": "bad request"},
            "401": {"description": "unauthorized"},
            "404": {"description": "not found"},
            "503": {"description": "unavailable"},
        }
    }
    assert postman._expected_statuses(op, "/api/v1/control/identity-probes/{probe_id}") == [
        400,
        401,
        404,
        503,
    ]


def test_nested_schema_refs_generate_structured_examples() -> None:
    doc = {
        "components": {
            "schemas": {
                "Address": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                        "zip": {"type": "integer"},
                    },
                },
                "Customer": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {"$ref": "#/components/schemas/Address"},
                    },
                },
            }
        }
    }
    value = postman._example(doc, {"$ref": "#/components/schemas/Customer"})
    assert value == {
        "address": {"city": "", "zip": 0},
        "name": "",
    }


def test_recursive_refs_fail_closed_without_infinite_recursion() -> None:
    doc = {
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "child": {"$ref": "#/components/schemas/Node"},
                        "name": {"type": "string"},
                    },
                }
            }
        }
    }
    value = postman._example(doc, {"$ref": "#/components/schemas/Node"})
    assert value == {"child": {}, "name": ""}


def test_generated_collection_matches_checked_in_artifact() -> None:
    collection, _ = postman.build()
    assert postman.OUTPUT.read_text(encoding="utf-8") == postman._json(collection)



def test_database_certification_requires_explicit_private_base_url() -> None:
    import json

    path = (
        ROOT
        / "postman"
        / "collections"
        / "Middleware-V3-Database-Certification.postman_collection.json"
    )
    collection = json.loads(path.read_text(encoding="utf-8"))
    prerequest = "\n".join(collection["event"][0]["script"]["exec"])
    assert "DB_PRIVATE_BASE_URL_REQUIRED" in prerequest
    assert "PRODUCTION_DATABASE_MUTATION_GATED" in prerequest
    assert "X-Codestra-Certification-Target" in prerequest

    private_requests = []
    public_negative_requests = []
    stack = list(collection["item"])
    while stack:
        item = stack.pop()
        stack.extend(item.get("item", []))
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        url = request.get("url", "")
        raw = url if isinstance(url, str) else url.get("raw", "")
        headers = request.get("header", [])
        marker = next(
            (
                h
                for h in headers
                if h.get("key") == "X-Codestra-Certification-Target"
            ),
            None,
        )
        if raw.startswith("{{db_private_base_url}}"):
            private_requests.append(request)
            assert marker is not None
            assert marker["value"] == "private"
        elif raw.startswith("{{base_url}}/internal/v1/database"):
            public_negative_requests.append(request)
            assert marker is None

    assert private_requests
    assert public_negative_requests
