from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.control_plane_auth import ControlPlaneCaller
from app.platform.api import _authorize_and_audit
from app.platform.persistence import record_authorization_decision
from app.platform.principal import principal_from_claims


class FakeConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, sql: str, *args: object) -> None:
        self.calls.append((sql, args))


class AcquireContext:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    async def __aenter__(self) -> FakeConnection:
        return self.connection

    async def __aexit__(self, *_args: object) -> None:
        return None


class FakePool:
    def __init__(self) -> None:
        self.connection = FakeConnection()

    def acquire(self) -> AcquireContext:
        return AcquireContext(self.connection)


def _principal():
    caller = ControlPlaneCaller(
        client_id="middleware-api",
        command_scope="platform.command",
        status_scope="platform.command.read",
        allowed_command_prefixes=(),
        allowed_targets=frozenset(),
        connector_commands_allowed=False,
        compatibility_only=False,
    )
    return principal_from_claims(
        {
            "sub": "user-1",
            "azp": "middleware-api",
            "tenant_id": "tenant-1",
            "scope": "platform.command platform.command.read",
            "roles": ["agent"],
        },
        caller,
        environment="test",
    )


def _request(pool: FakePool):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(runtime=SimpleNamespace(pool=pool))),
        state=SimpleNamespace(correlation_id="corr-request"),
    )


@pytest.mark.asyncio
async def test_authorization_audit_is_bounded_and_secret_free() -> None:
    pool = FakePool()
    await record_authorization_decision(
        pool,
        tenant_id="tenant-1",
        resource="connector:test",
        action="connector.read",
        principal_id="service-client",
        decision_code="ALLOW",
        allowed=True,
        correlation_id="c" * 240,
        effect_class="read",
        matched_policy="role_scope_policy",
    )

    sql, args = pool.connection.calls[-1]
    metadata = json.loads(str(args[6]))
    assert "middleware_control_audit" in sql
    assert "authorization_decision" in sql
    assert args[0] == "tenant-1"
    assert args[4] == "ALLOW"
    assert args[5] == "allowed"
    assert len(metadata["correlation_id"]) == 180
    assert metadata["matched_policy"] == "role_scope_policy"
    assert "Authorization" not in str(args[6])
    assert "Bearer" not in str(args[6])


@pytest.mark.asyncio
async def test_authorize_and_audit_persists_allow_and_deny_decisions() -> None:
    pool = FakePool()
    request = _request(pool)
    principal = _principal()

    allowed = await _authorize_and_audit(
        request,
        principal,
        action="connector.read",
        resource="connector:*",
        tenant_id="tenant-1",
        required_scopes=("platform.command.read",),
        environment="test",
    )
    denied = await _authorize_and_audit(
        request,
        principal,
        action="connector.read",
        resource="connector:*",
        tenant_id="tenant-2",
        required_scopes=("platform.command.read",),
        environment="test",
    )

    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.decision_code == "TENANT_MISMATCH"
    assert len(pool.connection.calls) == 2

    _, allow_args = pool.connection.calls[0]
    _, deny_args = pool.connection.calls[1]
    assert allow_args[5] == "allowed"
    assert deny_args[4] == "TENANT_MISMATCH"
    assert deny_args[5] == "denied"
