from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.commands import CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.core.config import Settings
from app.main import create_app
from app.operations import (
    MAX_BIGINT,
    MAX_INTEGER,
    _attempt_position,
    _decode_cursor,
    _encode_cursor,
    _event_position,
    _operation_position,
)
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError, RequestValidationError
from app.storage import MemoryInboxStore


class _ControlTokenVerifier:
    _TOKENS = {
        "middleware.request.forward": "legacy-command-token",
        "middleware.status.read": "legacy-status-token",
    }

    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        if (
            expected_client_id not in {"kong-gateway", "n8n-automation"}
            or authorization != f"Bearer {self._TOKENS[required_scope]}"
        ):
            raise AuthenticationError("invalid control token")
        return {
            "azp": "kong-gateway",
            "scope": required_scope,
            "tenant_id": "tenant-1",
            "sub": "user-123",
        }

    async def ready(self) -> bool:
        return True


def _app(settings: Settings):
    commands = CommandService(
        MemoryCommandStore(),
        CommandPolicyRegistry((), {}),
    )
    runtime = Runtime(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=_ControlTokenVerifier(),
        commands=commands,
    )
    # Includes the deprecated /v1/integrations/n8n/* aliases (monolith only).
    return create_app(settings=settings, runtime=runtime, legacy_monolith=True)


def _raw_cursor(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def test_operation_cursor_round_trip_is_canonical() -> None:
    command_id = uuid4()
    timestamp = datetime(2026, 9, 9, tzinfo=UTC)
    cursor = _encode_cursor(
        "operations",
        [timestamp.isoformat(), str(command_id)],
    )
    assert _operation_position(_decode_cursor(cursor, "operations")) == (
        timestamp,
        command_id,
    )


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "=",
        "A" * 513,
        _raw_cursor({"v": True, "kind": "operations", "position": [1, 2]}),
        _raw_cursor({"v": 2, "kind": "operations", "position": [1, 2]}),
        _raw_cursor({"v": 1, "kind": "operations", "position": [1, 2], "extra": False}),
        _raw_cursor({"v": 1, "kind": "events", "position": [1, 2]}),
        _encode_cursor("operations", [1, 2]) + "=",
    ],
)
def test_operation_cursor_rejects_noncanonical_envelopes(cursor: str) -> None:
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _decode_cursor(cursor, "operations")


def test_operation_cursor_rejects_duplicate_json_fields() -> None:
    duplicate = (
        base64.urlsafe_b64encode(
            b'{"v":1,"kind":"operations","kind":"events","position":[1,2]}'
        )
        .decode()
        .rstrip("=")
    )
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _decode_cursor(duplicate, "operations")


@pytest.mark.parametrize(
    "position",
    [
        ["2026-09-09T00:00:00", str(uuid4())],
        ["2026-09-09T00:00:00Z", str(uuid4())],
        [datetime(2026, 9, 9, tzinfo=UTC).isoformat(), str(uuid4()).upper()],
        [datetime(2026, 9, 9, tzinfo=UTC).isoformat(), 1],
    ],
)
def test_operation_cursor_rejects_noncanonical_positions(
    position: list[object],
) -> None:
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _operation_position(position)


@pytest.mark.parametrize("value", [True, 0, -1, MAX_BIGINT + 1, "1", 1.0])
def test_event_and_attempt_cursors_reject_non_bigint_positions(value: object) -> None:
    timestamp = datetime(2026, 9, 9, tzinfo=UTC).isoformat()
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _event_position([timestamp, value])
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _attempt_position([1, value])


def test_attempt_cursor_rejects_values_outside_postgresql_integer() -> None:
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _attempt_position([MAX_INTEGER + 1, 1])


@pytest.mark.parametrize(
    ("path", "kind", "position"),
    [
        (
            "/api/v1/operations",
            "operations",
            ["2026-09-09T00:00:00", str(UUID(int=1))],
        ),
        (
            "/api/v1/reconciliation/operations",
            "reconciliation",
            ["2026-09-09T00:00:00", 1],
        ),
        (
            "/api/v1/quarantine/events",
            "quarantine",
            ["2026-09-09T00:00:00", "event-1"],
        ),
    ],
)
def test_compatibility_lists_reject_naive_cursor_timestamps(
    test_settings: Settings,
    path: str,
    kind: str,
    position: list[object],
) -> None:
    headers = {
        "Authorization": "Bearer legacy-status-token",
        "X-Tenant-ID": "tenant-1",
    }
    cursor = _encode_cursor(kind, position)
    with TestClient(_app(test_settings)) as client:
        response = client.get(path, headers=headers, params={"cursor": cursor})
    assert response.status_code == 400


def test_attempt_list_rejects_cursor_outside_postgresql_integer(
    test_settings: Settings,
) -> None:
    headers = {
        "Authorization": "Bearer legacy-status-token",
        "X-Tenant-ID": "tenant-1",
    }
    cursor = _encode_cursor("attempts", [MAX_INTEGER + 1, 1])
    with TestClient(_app(test_settings)) as client:
        response = client.get(
            f"/v1/operations/{UUID(int=1)}/attempts",
            headers=headers,
            params={"cursor": cursor},
        )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "path",
    [
        "/v1/operations",
        "/v1/odoo/provider-health",
        f"/v1/integrations/n8n/operations/{UUID(int=1)}",
    ],
)
def test_control_surfaces_authenticate_before_tenant_validation(
    test_settings: Settings,
    path: str,
) -> None:
    with TestClient(_app(test_settings)) as client:
        invalid_tenant = {"X-Tenant-ID": "t" * 129}
        assert client.get(path, headers=invalid_tenant).status_code == 401
        authenticated = {
            **invalid_tenant,
            "Authorization": "Bearer legacy-status-token",
        }
        assert client.get(path, headers=authenticated).status_code == 400


@pytest.mark.parametrize(
    "path",
    [
        "/v1/operations",
        "/v1/odoo/provider-health",
        f"/v1/integrations/n8n/operations/{UUID(int=1)}",
    ],
)
def test_control_surfaces_reject_duplicate_authority_headers(
    test_settings: Settings,
    path: str,
) -> None:
    with TestClient(_app(test_settings)) as client:
        duplicate_auth = [
            ("Authorization", "Bearer legacy-status-token"),
            ("Authorization", "Bearer attacker-token"),
            ("X-Tenant-ID", "tenant-1"),
        ]
        assert client.get(path, headers=duplicate_auth).status_code == 400

        duplicate_tenant = [
            ("Authorization", "Bearer legacy-status-token"),
            ("X-Tenant-ID", "tenant-1"),
            ("X-Tenant-ID", "tenant-2"),
        ]
        assert client.get(path, headers=duplicate_tenant).status_code == 400


def test_operation_mutation_rejects_duplicate_idempotency_header(
    test_settings: Settings,
) -> None:
    headers = [
        ("Authorization", "Bearer legacy-command-token"),
        ("X-Tenant-ID", "tenant-1"),
        ("X-Correlation-ID", "correlation-1"),
        ("Idempotency-Key", "idem-one"),
        ("Idempotency-Key", "idem-two"),
    ]
    with TestClient(_app(test_settings)) as client:
        response = client.post(
            f"/v1/operations/{UUID(int=1)}/cancel",
            headers=headers,
            json={"expected_version": 1, "reason": "operator_requested"},
        )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "command_type=",
        f"command_type={'x' * 181}",
    ],
)
def test_n8n_operation_alias_preserves_canonical_query_bounds(
    test_settings: Settings,
    query: str,
) -> None:
    headers = {
        "Authorization": "Bearer legacy-status-token",
        "X-Tenant-ID": "tenant-1",
    }
    with TestClient(_app(test_settings)) as client:
        response = client.get(
            f"/v1/integrations/n8n/operations?{query}", headers=headers
        )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "path",
    [
        "/v1/odoo/commands",
        "/v1/integrations/n8n/commands",
    ],
)
def test_command_surfaces_reject_duplicate_idempotency_header(
    test_settings: Settings,
    path: str,
) -> None:
    command_id = str(uuid4())
    payload = {
        "command_id": command_id,
        "command_type": "crm.contact.create.v1",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "user-123",
        "correlation_id": "correlation-1",
        "idempotency_key": "idem-one",
        "capability": "ODOO_WRITE",
        "payload": {"contact_id": "contact-1"},
    }
    headers = [
        ("Authorization", "Bearer legacy-command-token"),
        ("X-Tenant-ID", "tenant-1"),
        ("X-Correlation-ID", "correlation-1"),
        ("Idempotency-Key", "idem-one"),
        ("Idempotency-Key", "idem-two"),
    ]
    with TestClient(_app(test_settings)) as client:
        response = client.post(path, headers=headers, json=payload)
    assert response.status_code == 400
