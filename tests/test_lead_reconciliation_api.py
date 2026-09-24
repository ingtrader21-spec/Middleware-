from app.main import app


def test_reconciliation_routes_are_staging_scoped():
    schema = app.openapi()
    start = schema["paths"]["/api/v1/crm-vicidial/reconciliation/start"]["post"]
    request_schema = start["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema
    assert "/api/v1/crm-vicidial/reconciliation/{run_id}/finish" in schema["paths"]
