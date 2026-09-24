import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import controller as controller_api
from app.core.controller import ApprovalTokens, ControllerError, RestrictedController


TENANT = "tenant-synthetic-001"
HEADERS = {
    "X-Tenant-ID": TENANT,
    "X-Request-ID": "request-synthetic-001",
    "X-Correlation-ID": "correlation-synthetic-001",
    "Idempotency-Key": "fixture-key-controller-001",
}


@pytest.fixture
def domain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RestrictedController:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    instance = RestrictedController(
        ApprovalTokens(b"fixture-controller-signing-material-32-bytes-minimum", 60),
        (workspace,),
    )
    monkeypatch.setattr(controller_api, "_controller", lambda: instance)
    return instance


@pytest.fixture
def client(domain: RestrictedController) -> TestClient:
    app = FastAPI()
    app.include_router(controller_api.router)
    return TestClient(app)


def task_body(domain: RestrictedController) -> dict[str, str]:
    return {
        "title": "Synthetic controller task",
        "objective": "Inspect and validate the isolated fixture workspace",
        "workspace": str(domain.workspaces[0]),
    }


def create_and_plan(client: TestClient, domain: RestrictedController):
    created = client.post("/api/v1/tasks", headers=HEADERS, json=task_body(domain))
    assert created.status_code == 201
    task = created.json()
    planned = client.post(
        f"/api/v1/tasks/{task['task_id']}/plan",
        headers=HEADERS,
        json={"steps": [{"tool": "git_status", "arguments": {}}]},
    )
    assert planned.status_code == 200
    assert planned.json()["state"] == "AWAITING_APPROVAL"
    return planned.json()


def approve(client: TestClient, task: dict):
    response = client.post(
        f"/api/v1/tasks/{task['task_id']}/approve",
        headers={**HEADERS, "X-Actor-ID": "synthetic-reviewer"},
        json={"plan_hash": task["plan_hash"], "server_id": "middleware"},
    )
    assert response.status_code == 200
    return response.json()


def test_task_creation_idempotency_state_and_tenant_isolation(client, domain):
    first = client.post("/api/v1/tasks", headers=HEADERS, json=task_body(domain))
    replay = client.post("/api/v1/tasks", headers=HEADERS, json=task_body(domain))
    assert first.status_code == 201
    assert replay.json()["task_id"] == first.json()["task_id"]
    assert replay.json()["idempotent_replay"] is True
    conflict = client.post(
        "/api/v1/tasks", headers=HEADERS,
        json={**task_body(domain), "title": "Conflicting request"},
    )
    assert conflict.status_code == 409
    hidden = client.get(
        f"/api/v1/tasks/{first.json()['task_id']}",
        headers={**HEADERS, "X-Tenant-ID": "tenant-other"},
    )
    assert hidden.status_code == 404


def test_unknown_fields_invalid_transition_tools_raw_shell_and_traversal(client, domain):
    unknown = client.post(
        "/api/v1/tasks", headers=HEADERS,
        json={**task_body(domain), "unexpected": True},
    )
    assert unknown.status_code == 422
    task = client.post("/api/v1/tasks", headers=HEADERS, json=task_body(domain)).json()
    invalid = client.post(
        f"/api/v1/tasks/{task['task_id']}/approve",
        headers={**HEADERS, "X-Actor-ID": "reviewer"},
        json={"plan_hash": "a" * 64, "server_id": "middleware"},
    )
    assert invalid.status_code == 409
    for step in (
        {"tool": "unknown", "arguments": {}},
        {"tool": "git_status", "arguments": {"command": "id"}},
    ):
        denied = client.post(
            f"/api/v1/tasks/{task['task_id']}/plan",
            headers=HEADERS, json={"steps": [step]},
        )
        assert denied.status_code == 403
    traversal_headers = {**HEADERS, "Idempotency-Key": "fixture-key-traversal"}
    traversal = client.post(
        "/api/v1/tasks", headers=traversal_headers,
        json={**task_body(domain), "workspace": str(domain.workspaces[0] / ".." / "escape")},
    )
    assert traversal.status_code == 403


def test_token_tampering_expiration_replay_and_scope(domain):
    task, _ = domain.create_task(
        task_body(domain), tenant_id=TENANT, request_id="r", correlation_id="c",
        idempotency_key="fixture-key-domain",
    )
    domain.plan(task.task_id, TENANT, [{"tool": "git_status", "arguments": {}}])
    task, token = domain.approve(task.task_id, TENANT, task.plan_hash, "reviewer", "middleware")
    common = dict(task_id=task.task_id, tenant_id=TENANT, server_id="middleware",
                  workspace=task.workspace, tool="git_status")
    with pytest.raises(ControllerError, match="invalid"):
        domain.tokens.verify(token[:-1] + ("A" if token[-1] != "A" else "B"), consume=False, **common)
    claims = domain.tokens.verify(token, consume=False, **common)
    with pytest.raises(ControllerError, match="expired"):
        domain.tokens.verify(token, consume=False, now=claims["exp"], **common)
    with pytest.raises(ControllerError, match="scope"):
        domain.tokens.verify(token, consume=False, **{**common, "server_id": "qwen"})
    with pytest.raises(ControllerError, match="scope"):
        domain.tokens.verify(token, consume=False, **{**common, "workspace": str(domain.workspaces[0] / "other")})
    domain.tokens.verify(token, consume=True, **common)
    with pytest.raises(ControllerError, match="replay"):
        domain.tokens.verify(token, consume=True, **common)


def test_execution_audit_redaction_and_signed_verification(client, domain):
    task = create_and_plan(client, domain)
    approved = approve(client, task)
    response = client.post(
        "/api/v1/tools/execute", headers=HEADERS,
        json={
            "task_id": task["task_id"], "server_id": "middleware",
            "workspace": task["workspace"], "tool": "git_status", "arguments": {},
            "approval_token": approved["approval_token"],
        },
    )
    assert response.status_code == 202
    execution = response.json()
    audit = client.get(f"/api/v1/audit/{task['task_id']}", headers=HEADERS).json()
    assert len(audit["records"]) == 4
    assert audit["records"][-1]["previous_hash"] == audit["records"][-2]["record_hash"]
    verification = client.get(
        f"/api/v1/verifications/{execution['verification_code']}", headers=HEADERS
    ).json()
    signature = verification.pop("signature")
    canonical = json.dumps(verification, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(domain.tokens._secret, canonical, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, expected)
    assert verification["evidence_hash"] == execution["evidence_hash"]
    assert "secret" not in json.dumps(audit).lower()


def test_api_contract_contains_all_required_routes(client):
    routes = {
        (path, method.upper())
        for path, definition in client.app.openapi()["paths"].items()
        for method in definition
    }
    required = {
        ("/api/v1/tasks", "POST"), ("/api/v1/tasks/{task_id}", "GET"),
        ("/api/v1/tasks/{task_id}/plan", "POST"),
        ("/api/v1/tasks/{task_id}/approve", "POST"),
        ("/api/v1/tasks/{task_id}/cancel", "POST"),
        ("/api/v1/executions", "POST"),
        ("/api/v1/executions/{execution_id}", "GET"),
        ("/api/v1/tools/execute", "POST"),
        ("/api/v1/verifications/{verification_code}", "GET"),
        ("/api/v1/audit/{task_id}", "GET"),
        ("/api/v1/agents/register", "POST"),
        ("/api/v1/agents", "GET"),
    }
    assert required <= routes


def test_agent_inventory_is_exact_private_disabled_and_conflict_safe(client):
    registrations = {
        "middleware": ("spiffe://codestra.internal/agent/middleware", "10.40.0.1:9443", "DEVELOPMENT"),
        "qwen": ("spiffe://codestra.internal/agent/qwen", "10.40.0.4:9443", "DEVELOPMENT"),
        "web": ("spiffe://codestra.internal/agent/web", "10.40.0.3:9443", "DEVELOPMENT"),
        "vici": ("spiffe://codestra.internal/agent/vici", "10.40.0.2:9444", "PRODUCTION_OBSERVER"),
    }
    for index, (server, (spiffe, endpoint, profile)) in enumerate(registrations.items(), 1):
        response = client.post("/api/v1/agents/register", json={
            "server_id": server, "spiffe_id": spiffe,
            "private_endpoint": endpoint, "profile": profile,
            "certificate_sha256": f"{index:064x}",
            "certificate_serial": str(1000 + index),
            "not_after": "2026-09-05T00:00:00Z",
            "rotation_owner": "fixture-security-owner",
            "public_listener": False,
        })
        assert response.status_code == 201
        assert response.json()["enabled"] is False
    inventory = client.get("/api/v1/agents").json()["agents"]
    assert {item["server_id"] for item in inventory} == set(registrations)
    denied = client.post("/api/v1/agents/register", json={
        "server_id": "qwen", "spiffe_id": registrations["qwen"][0],
        "private_endpoint": "0.0.0.0:9443", "profile": "DEVELOPMENT",
        "certificate_sha256": "a" * 64, "certificate_serial": "2000",
        "not_after": "2026-09-05T00:00:00Z", "rotation_owner": "owner",
        "public_listener": True,
    })
    assert denied.status_code == 403


def test_public_middleware_does_not_mount_controller_routes():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert "app.api.v1.controller" not in source
    assert "controller_router" not in source


def test_private_entrypoint_has_health_and_readiness():
    from app.entrypoints.controller_api import app

    paths = set(app.openapi()["paths"])
    assert {"/healthz", "/readyz", "/api/v1/tasks"} <= paths
