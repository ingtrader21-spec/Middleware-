from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.api_inputs import authorization_header, optional_header, required_header
from app.core.config import Settings
from app.control_api import (
    MAX_BIGINT,
    _audit_cursor,
    _audit_next,
    _cursor,
    _next,
)
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import RequestValidationError
from app.storage import MemoryInboxStore


class _StatusTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        assert authorization == "Bearer legacy-status-token"
        assert expected_client_id == "kong-gateway"
        assert required_scope == "middleware.status.read"
        return {
            "azp": "kong-gateway",
            "scope": required_scope,
            "tenant_id": "tenant-1",
            "sub": "user-123",
        }

    async def ready(self) -> bool:
        return True


def _encode(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _request(*headers: tuple[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "headers": [
                (name.lower().encode(), value.encode()) for name, value in headers
            ],
        }
    )


def test_cursor_round_trip_is_canonical_and_bounded() -> None:
    assert _cursor(None) is None
    assert _cursor(_next(1)) == 1
    assert _cursor(_next(MAX_BIGINT)) == MAX_BIGINT


@pytest.mark.parametrize("row_id", [True, 0, -1, MAX_BIGINT + 1])
def test_cursor_encoder_rejects_non_database_ids(row_id: int) -> None:
    with pytest.raises(ValueError, match="PostgreSQL bigint range"):
        _next(row_id)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "=",
        "A" * 129,
        _encode({"v": 1, "id": True}),
        _encode({"v": True, "id": 1}),
        _encode({"v": 1, "id": 0}),
        _encode({"v": 1, "id": MAX_BIGINT + 1}),
        _encode({"v": 1, "id": 1, "extra": False}),
        _next(1) + "=",
        _encode("not-an-object"),
        _encode({"v": 2, "id": 1}),
    ],
)
def test_cursor_rejects_malformed_or_noncanonical_values(value: str) -> None:
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _cursor(value)


def test_cursor_rejects_duplicate_json_fields() -> None:
    duplicate = base64.urlsafe_b64encode(b'{"v":1,"id":1,"id":2}').decode().rstrip("=")
    with pytest.raises(RequestValidationError, match="cursor is malformed"):
        _cursor(duplicate)


def test_audit_cursor_round_trip_preserves_total_order_position() -> None:
    created_at = datetime(2026, 9, 9, 12, 30, 45, 123456, tzinfo=UTC)
    encoded = _audit_next(created_at, "control", MAX_BIGINT)
    assert _audit_cursor(encoded) == (created_at, "control", MAX_BIGINT)


@pytest.mark.parametrize(
    "value",
    [
        "",
        _encode({"v": 1, "ts": "2026-09-09T12:30:45Z", "authority": "other", "id": 1}),
        _encode({"v": 1, "ts": "2026-09-09T12:30:45", "authority": "control", "id": 1}),
        _encode({"v": 1, "ts": "invalid", "authority": "control", "id": 1}),
        _encode(
            {"v": 1, "ts": "2026-09-09T12:30:45Z", "authority": "command", "id": 0}
        ),
        _encode(
            {"v": 2, "ts": "2026-09-09T12:30:45Z", "authority": "command", "id": 1}
        ),
    ],
)
def test_audit_cursor_rejects_malformed_positions(value: str) -> None:
    with pytest.raises(RequestValidationError, match="audit cursor is malformed"):
        _audit_cursor(value)


def test_required_header_accepts_one_canonical_value() -> None:
    request = _request(("X-Tenant-ID", "tenant-1"))
    assert (
        required_header(
            request,
            "X-Tenant-ID",
            minimum=1,
            maximum=128,
        )
        == "tenant-1"
    )


@pytest.mark.parametrize(
    ("name", "value", "minimum", "maximum"),
    [
        ("X-Tenant-ID", "", 1, 128),
        ("X-Tenant-ID", "t" * 129, 1, 128),
        ("X-Correlation-ID", "", 1, 180),
        ("X-Correlation-ID", "c" * 181, 1, 180),
        ("Idempotency-Key", "short", 8, 180),
        ("Idempotency-Key", "i" * 181, 8, 180),
    ],
)
def test_required_header_rejects_invalid_contract_values(
    name: str,
    value: str,
    minimum: int,
    maximum: int,
) -> None:
    request = _request((name, value))
    with pytest.raises(RequestValidationError, match=f"{name} is malformed"):
        required_header(
            request,
            name,
            minimum=minimum,
            maximum=maximum,
        )


def test_required_header_rejects_missing_and_duplicate_values() -> None:
    missing = _request()
    with pytest.raises(RequestValidationError, match="provided exactly once"):
        required_header(missing, "X-Tenant-ID", minimum=1, maximum=128)

    duplicate = _request(
        ("Authorization", "Bearer first"),
        ("Authorization", "Bearer second"),
    )
    with pytest.raises(RequestValidationError, match="provided at most once"):
        authorization_header(duplicate)


def test_authorization_header_preserves_missing_authentication_semantics() -> None:
    assert authorization_header(_request()) == ""
    with pytest.raises(RequestValidationError, match="Authorization is malformed"):
        authorization_header(_request(("Authorization", "x" * 8193)))


def test_optional_header_accepts_absence_or_one_bounded_value() -> None:
    assert (
        optional_header(
            _request(),
            "X-Tenant-ID",
            minimum=1,
            maximum=128,
        )
        is None
    )
    assert (
        optional_header(
            _request(("X-Tenant-ID", "tenant-1")),
            "X-Tenant-ID",
            minimum=1,
            maximum=128,
        )
        == "tenant-1"
    )


def test_optional_header_rejects_duplicates_and_malformed_values() -> None:
    duplicate = _request(
        ("X-Tenant-ID", "tenant-1"),
        ("X-Tenant-ID", "tenant-2"),
    )
    with pytest.raises(RequestValidationError, match="provided at most once"):
        optional_header(
            duplicate,
            "X-Tenant-ID",
            minimum=1,
            maximum=128,
        )

    with pytest.raises(RequestValidationError, match="X-Tenant-ID is malformed"):
        optional_header(
            _request(("X-Tenant-ID", "")),
            "X-Tenant-ID",
            minimum=1,
            maximum=128,
        )


def test_authentication_precedes_tenant_validation(test_settings: Settings) -> None:
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=_StatusTokenVerifier(),
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        invalid_tenant = {"X-Tenant-ID": "t" * 129}
        assert (
            client.get("/v1/system/capabilities", headers=invalid_tenant).status_code
            == 401
        )
        authenticated = {
            **invalid_tenant,
            "Authorization": "Bearer legacy-status-token",
        }
        assert (
            client.get("/v1/system/capabilities", headers=authenticated).status_code
            == 400
        )
