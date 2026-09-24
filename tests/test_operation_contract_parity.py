from pathlib import Path

from app.main import create_app


OPERATION_ROUTES = {
    ("GET", "/v1/operations"),
    ("GET", "/v1/operations/{command_id}"),
    ("GET", "/v1/operations/{command_id}/events"),
    ("GET", "/v1/operations/{command_id}/attempts"),
    ("POST", "/v1/operations/{command_id}/cancel"),
    ("POST", "/v1/operations/{command_id}/reconcile"),
}


def test_runtime_openapi_and_canonical_contract_have_operation_route_parity(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    runtime = {(method.upper(), path) for path, value in schema["paths"].items() for method in value if method.lower() in {"get", "post"}}
    assert OPERATION_ROUTES <= runtime
    contract = Path("contracts/platform/integration-fabric-api.v2.yaml").read_text(encoding="utf-8")
    for _, path in OPERATION_ROUTES:
        assert f"  {path}:" in contract
    assert "status_scope" in contract
    assert "command_scope" in contract
    assert "operations.cancel" not in contract
    assert "operations.reconcile" not in contract


def test_operation_openapi_exposes_bounds_and_versioned_mutation_model(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    list_parameters = schema["paths"]["/v1/operations"]["get"]["parameters"]
    limit = next(item for item in list_parameters if item["name"] == "limit")
    assert limit["schema"]["maximum"] == 100
    mutation = schema["components"]["schemas"]["OperationMutationRequest"]
    assert set(mutation["required"]) == {"expected_version", "reason"}


def test_operation_success_responses_use_typed_schemas(test_settings) -> None:
    schema = create_app(settings=test_settings).openapi()
    expected = {
        ("/v1/operations", "get", "OperationListResponse"),
        ("/v1/operations/{command_id}", "get", "OperationResponse"),
        ("/v1/operations/{command_id}/events", "get", "OperationEventListResponse"),
        ("/v1/operations/{command_id}/attempts", "get", "OperationAttemptListResponse"),
        ("/v1/operations/{command_id}/cancel", "post", "OperationResponse"),
        ("/v1/operations/{command_id}/reconcile", "post", "OperationResponse"),
    }
    for path, method, model in expected:
        response = schema["paths"][path][method]["responses"]["200"]
        assert response["content"]["application/json"]["schema"] == {
            "$ref": f"#/components/schemas/{model}"
        }
    assert "duplicate" in schema["components"]["schemas"]["OperationResponse"]["required"]
