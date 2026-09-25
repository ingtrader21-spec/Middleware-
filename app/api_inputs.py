from __future__ import annotations

from typing import Any

from fastapi import Request

from .control_plane_auth import ControlPlaneCaller, caller_for_authorization
from .security import AuthorizationError, RequestValidationError, SecurityError, authorize_tenant


async def restrict_sms_identity(request: Request) -> None:
    # This global dependency can only deny. The canonical endpoints still
    # verify the original JWT, scope and tenant before any read or submission.
    # Telnexa's exact callback uses its own shared API-key + HMAC contract;
    # do not classify that opaque key as an Odoo JWT caller before the route
    # has authenticated it.
    if request.method == "POST" and request.url.path in {
        "/api/v1/events/telnexa",
        "/api/v1/events/telnexa/verify",
        "/api/v1/events/klyrow",
    }:
        return
    try:
        caller = caller_for_authorization(request.headers.get("Authorization", ""))
    except SecurityError:
        return
    if caller.client_id == "odoo-sms" and (request.method, request.url.path) not in {
        ("POST", "/v1/communications/messages"),
        ("GET", "/v1/communications/messages/by-idempotency"),
    }:
        raise AuthorizationError("SMS bridge is restricted to message submission and idempotency readback")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def required_header(
    request: Request,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> str:
    values = request.headers.getlist(name)
    if len(values) != 1:
        raise RequestValidationError(f"{name} must be provided exactly once")
    value = values[0]
    if not minimum <= len(value) <= maximum:
        raise RequestValidationError(f"{name} is malformed")
    return value


def optional_header(
    request: Request,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> str | None:
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise RequestValidationError(f"{name} must be provided at most once")
    if not values:
        return None
    value = values[0]
    if not minimum <= len(value) <= maximum:
        raise RequestValidationError(f"{name} is malformed")
    return value


def authorization_header(request: Request) -> str:
    values = request.headers.getlist("Authorization")
    if len(values) > 1:
        raise RequestValidationError("Authorization must be provided at most once")
    value = values[0] if values else ""
    if len(value) > 8192:
        raise RequestValidationError("Authorization is malformed")
    return value


async def authenticated_tenant(
    request: Request,
    *,
    mutation: bool = False,
) -> tuple[ControlPlaneCaller, dict[str, Any], str]:
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    claims = await request.app.state.runtime.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=caller.command_scope if mutation else caller.status_scope,
    )
    tenant = required_header(
        request,
        "X-Tenant-ID",
        minimum=1,
        maximum=128,
    )
    authorize_tenant(claims, tenant)
    return caller, claims, tenant
