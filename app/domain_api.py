from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from .api_inputs import authenticated_tenant, required_header
from .commands import (
    CommandCapabilityDisabled,
    CommandEnvelope,
    OperationMutationRequest,
)
from .control_plane_auth import authorize_command
from .legacy_effects import DENIED_RESPONSES, denial_dependency, deny
from .operations import (
    OperationApiState,
    OperationResponse,
    _mutation_context,
    _operation_json,
    list_operations as core_list_operations,
)
from .security import AuthorizationError, RequestValidationError
from .storage import StorageError
from .telephony_api import compat_router as calling_compat_router
from .telephony_api import router as calling_router

router = APIRouter(tags=["domain-control"])
router.include_router(calling_router)
router.include_router(calling_compat_router)

_PREFIXES = {
    "odoo": "crm.",
    "crm": "crm.",
    "email": "email.",
    "sms": "sms.",
    "telephony": "telephony.",
    "social": "social.",
    "marketing": "marketing.",
    "ai": "ai.",
}


async def _submit(domain: str, command: CommandEnvelope, request: Request):
    active = request.app.state.runtime
    caller, claims, tenant = await authenticated_tenant(request, mutation=True)
    correlation = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    prefix = _PREFIXES[domain]
    if not command.command_type.startswith(prefix):
        raise RequestValidationError(
            f"{domain} command_type must use {prefix} namespace"
        )
    authorize_command(caller, command_type=command.command_type, target=command.target)
    if (
        tenant != command.tenant_id
        or correlation != command.correlation_id
        or idempotency != command.idempotency_key
    ):
        raise RequestValidationError(
            "tenant, correlation, and idempotency headers must match command"
        )
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthorizationError("token subject is required")
    if (
        caller.client_id == "n8n-automation"
        and active.settings.umbrella_controls.get("N8N_EXTERNAL_PROVIDER_WRITES")
        is not True
    ):
        raise CommandCapabilityDisabled("N8N_EXTERNAL_PROVIDER_WRITES is disabled")
    operation = await active.commands.submit(
        command, authenticated_subject=subject, authenticated_client_id=caller.client_id
    )
    return JSONResponse(
        status_code=200 if operation.duplicate else 202,
        content=_operation_json(operation),
        headers={
            "Location": f"/v1/{domain}/operations/{operation.command_id}",
            "X-Correlation-ID": operation.correlation_id,
        },
    )


def _submit_handler(domain: str):
    async def handler(command: CommandEnvelope, request: Request):
        return await _submit(domain, command, request)

    return handler


for _domain in (
    "odoo",
    "crm",
    "email",
    "sms",
    "telephony",
    "social",
    "marketing",
    "ai",
):
    router.add_api_route(
        f"/v1/{_domain}/commands",
        _submit_handler(_domain),
        methods=["POST"],
        name=f"submit_{_domain}_command",
        response_model=OperationResponse,
        responses={
            202: {"model": OperationResponse, "description": "Command accepted"}
        },
    )


async def _get(domain: str, operation_id: UUID, request: Request):
    active = request.app.state.runtime
    _, _, tenant = await authenticated_tenant(request)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    operation = await active.commands.get(tenant, operation_id)
    if not operation.command_type.startswith(_PREFIXES[domain]):
        from .commands import CommandNotFound

        raise CommandNotFound("operation was not found")
    return JSONResponse(content=_operation_json(operation))


def _detail_handler(domain: str):
    async def handler(operation_id: UUID, request: Request):
        return await _get(domain, operation_id, request)

    return handler


for _domain in (
    "odoo",
    "crm",
    "email",
    "sms",
    "telephony",
    "social",
    "marketing",
    "ai",
):
    router.add_api_route(
        f"/v1/{_domain}/operations/{{operation_id}}",
        _detail_handler(_domain),
        methods=["GET"],
        name=f"get_{_domain}_operation",
    )


async def _list_domain(domain: str, request: Request):
    active = request.app.state.runtime
    _, _, tenant = await authenticated_tenant(request)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    rows = await active.commands.list_operations(tenant, limit=100)
    return {
        "items": [
            _operation_json(row)
            for row in rows
            if row.command_type.startswith(_PREFIXES[domain])
        ],
        "next_cursor": None,
    }


def _list_handler(domain: str):
    async def handler(request: Request):
        return await _list_domain(domain, request)

    return handler


for _domain in (
    "odoo",
    "crm",
    "email",
    "sms",
    "telephony",
    "social",
    "marketing",
    "ai",
):
    router.add_api_route(
        f"/v1/{_domain}/operations",
        _list_handler(_domain),
        methods=["GET"],
        name=f"list_{_domain}_operations",
    )


async def _mutate(
    domain: str,
    operation_id: UUID,
    body: OperationMutationRequest,
    request: Request,
    action: str,
):
    service, tenant, actor, idem = await _mutation_context(request)
    current = await service.get(tenant, operation_id)
    if not current.command_type.startswith(_PREFIXES[domain]):
        from .commands import CommandNotFound

        raise CommandNotFound("operation was not found")
    operation = await service.mutate_operation(
        tenant,
        operation_id,
        action=action,
        actor_id=actor,
        idempotency_key=idem,
        expected_version=body.expected_version,
        reason=body.reason,
    )
    return JSONResponse(content=_operation_json(operation))


def _mutation_handler(domain: str, action: str):
    async def handler(
        operation_id: UUID, body: OperationMutationRequest, request: Request
    ):
        return await _mutate(domain, operation_id, body, request, action)

    return handler


for _domain in ("odoo", "crm", "telephony", "social", "marketing", "ai"):
    for _action in ("cancel", "reconcile"):
        router.add_api_route(
            f"/v1/{_domain}/operations/{{operation_id}}/{_action}",
            _mutation_handler(_domain, _action),
            methods=["POST"],
            name=f"{_action}_{_domain}_operation",
        )


# Legacy n8n operation aliases. The canonical Middleware edge contract
# classifies every /v1/integrations/n8n/* path as ``denied``: Kong and Caddy
# return 404 for them and the deployed application never mounts this router
# (``app.router_registry.LEGACY_MONOLITH_ONLY_ROUTERS``). The listing read
# remains on the in-process monolith until the published sunset as read-only
# compatibility; the cancel/reconcile mutations are permanently denied by
# config/legacy-effect-registry.v1.json.
_LEGACY_ALIAS_SUNSET = "Wed, 30 Jun 2027 23:59:59 GMT"
legacy_n8n_router = APIRouter(tags=["domain-control-legacy-n8n"])


def _legacy_alias_headers(successor: str) -> dict[str, str]:
    return {
        "Deprecation": "true",
        "Sunset": _LEGACY_ALIAS_SUNSET,
        "Link": f'<{successor}>; rel="successor-version"',
    }


@legacy_n8n_router.get("/v1/integrations/n8n/operations", deprecated=True)
async def n8n_operations(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
    state: OperationApiState | None = None,
    command_type: str | None = Query(None, min_length=1, max_length=180),
):
    response = await core_list_operations(
        request=request,
        limit=limit,
        cursor=cursor,
        state=state,
        command_type=command_type,
    )
    response.headers.update(_legacy_alias_headers("/v2/automation/commands"))
    return response


@legacy_n8n_router.post(
    "/v1/integrations/n8n/operations/{operation_id}/cancel",
    deprecated=True,
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-N8N-V1-OPERATION-CANCEL"))],
)
async def n8n_cancel() -> None:
    """Permanently denied (``LE-N8N-V1-OPERATION-CANCEL``); use ``/v1/operations``."""
    deny("LE-N8N-V1-OPERATION-CANCEL")


@legacy_n8n_router.post(
    "/v1/integrations/n8n/operations/{operation_id}/reconcile",
    deprecated=True,
    responses=DENIED_RESPONSES,
    dependencies=[Depends(denial_dependency("LE-N8N-V1-OPERATION-RECONCILE"))],
)
async def n8n_reconcile() -> None:
    """Permanently denied (``LE-N8N-V1-OPERATION-RECONCILE``); use ``/v1/operations``."""
    deny("LE-N8N-V1-OPERATION-RECONCILE")


async def _health(request: Request, provider: str):
    await _get_auth(request)
    return {
        "provider": provider,
        "status": "DISABLED",
        "external_effects": False,
        "writes_enabled": False,
    }


async def _get_auth(request: Request):
    await authenticated_tenant(request)


@router.get("/v1/odoo/provider-health")
async def odoo_health(request: Request):
    return await _health(request, "odoo-19")


@router.get("/v1/ai/provider-health")
async def ai_health(request: Request):
    return await _health(request, "external-models")


@router.get("/v1/providers/status")
async def provider_status(request: Request):
    await _get_auth(request)
    return {
        "external_effects": "DISABLED",
        "providers": [
            {"provider": p, "status": "DISABLED"}
            for p in (
                "odoo-19",
                "klyrow-email",
                "telnexa-sms",
                "vicidial-restricted",
                "postly-social",
                "external-models",
            )
        ],
    }


@router.post("/v1/odoo/mappings/validate")
@router.post("/v1/crm/mappings/validate")
async def mapping_validate(document: dict[str, object], request: Request):
    await _get_auth(request)
    if not document or any(not isinstance(k, str) or not k for k in document):
        raise RequestValidationError("mapping document is invalid")
    return {"valid": True, "external_effects": False, "field_count": len(document)}
