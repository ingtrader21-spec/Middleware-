from __future__ import annotations

from fastapi import FastAPI

from app.api.v1 import agent_provisioning


def test_provisioning_read_and_transition_openapi_expose_verified_tenant_selector() -> None:
    app = FastAPI()
    app.include_router(agent_provisioning.router)
    document = app.openapi()
    expected = (
        "/platform/v1/agent-provisioning/requests/{request_id}",
        "/platform/v1/agent-provisioning/requests/{request_id}/reconcile",
        "/platform/v1/agent-provisioning/requests/{request_id}/suspend",
        "/platform/v1/agent-provisioning/requests/{request_id}/reactivate",
        "/platform/v1/agent-provisioning/requests/{request_id}/revoke",
    )
    for path in expected:
        operation = next(iter(document["paths"][path].values()))
        parameters = operation.get("parameters", [])
        header = next(
            item for item in parameters
            if item.get("in") == "header" and item.get("name") == "X-Codestra-Tenant-ID"
        )
        assert header["required"] is False
