from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from app.agent.executor import AgentExecutor
from app.agent.security import CONTROLLER_SPIFFE, certificate_identity
from app.core.controller import ControllerError


def certificate_der(spiffe: str) -> bytes:
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-controller")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe)]),
            critical=False,
        )
        .sign(key, algorithm=None)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_identity_is_derived_from_certificate_and_headers_are_irrelevant():
    der = certificate_der(CONTROLLER_SPIFFE)
    identity, fingerprint = certificate_identity(
        {"extensions": {"tls": {"client_cert": der}},
         "headers": [(b"x-verified-client-spiffe-id", b"spiffe://attacker")]}
    )
    assert identity == CONTROLLER_SPIFFE
    assert len(fingerprint) == 64


def test_missing_and_wrong_client_certificate_are_rejected():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as missing:
        certificate_identity({})
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong:
        certificate_identity(
            {"extensions": {"tls": {"client_cert": certificate_der("spiffe://wrong")}}}
        )
    assert wrong.value.status_code == 403


@pytest.mark.asyncio
async def test_safe_workspace_tools_and_output(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "example.py").write_text("safe marker\n")
    executor = AgentExecutor((workspace,))
    context = {"tenant_id": "fixture-tenant", "request_id": "fixture-request",
               "correlation_id": "fixture-correlation"}
    inspected = await executor.execute("inspect_workspace", str(workspace), {}, context)
    assert inspected["state"] == "COMPLETED"
    files = await executor.execute("list_files", str(workspace), {}, context)
    assert files["result"]["files"] == ["example.py"]
    read = await executor.execute(
        "read_file", str(workspace), {"path": "example.py"}, context
    )
    assert read["result"]["content"] == "safe marker\n"
    searched = await executor.execute(
        "search_code", str(workspace), {"query": "marker"}, context
    )
    assert searched["result"]["matches"] == [{"path": "example.py", "line": 1}]


@pytest.mark.asyncio
async def test_raw_shell_unknown_tool_path_traversal_and_service_scope_fail_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executor = AgentExecutor((workspace,))
    context = {"tenant_id": "fixture-tenant", "request_id": "fixture-request",
               "correlation_id": "fixture-correlation"}
    with pytest.raises(ControllerError, match="forbidden field"):
        await executor.execute(
            "inspect_workspace", str(workspace), {"command": "id"}, context
        )
    with pytest.raises(ControllerError, match="unknown tool"):
        await executor.execute("generic_shell", str(workspace), {}, context)
    traversed = await executor.execute(
        "read_file", str(workspace), {"path": "../outside"}, context
    )
    assert traversed["state"] == "FAILED"
    service = await executor.execute(
        "check_service", str(workspace), {"service": "ssh"}, context
    )
    assert service["state"] == "FAILED"


def test_agent_contract_and_inactive_defaults():
    from app.core.config import settings
    from app.entrypoints.server_a_agent import app

    paths = set(app.openapi()["paths"])
    assert {
        "/api/v1/tools/execute", "/api/v1/tools/cancel",
        "/api/v1/executions/{execution_id}",
        "/api/v1/services/{service}/status", "/api/v1/workspaces",
        "/healthz", "/readyz",
    } <= paths
    assert settings.server_a_agent_enabled is False
    assert settings.server_a_agent_bind == "10.40.0.1:9443"
