"""Appolon control-plane routes as a mountable router.

These operations used to be defined inline in ``app.appolon_factory``; they
are now an :class:`~fastapi.APIRouter` mounted by the single application
factory in :mod:`app.application`. Every handler reaches its dependencies
through ``request.app.state.runtime`` (the :class:`RuntimeContainer`) and
``request.app.state.observability``; nothing here opens a resource.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError as FastApiValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from .api_inputs import (
    authenticated_tenant,
    authorization_header,
    optional_header,
    required_header,
)
from .commands import CommandCapabilityDisabled, CommandEnvelope, CommandError
from .communications import (
    CHANNEL_COMMAND,
    CommunicationEventPage,
    CommunicationMessage,
    CommunicationMessagePage,
    CommunicationUsageReport,
    CommunicationsError,
    CommunicationsNotFound,
    CommunicationsService,
    CreateMessageRequest,
    MemoryCommunicationsStore,
    Paged,
    ProviderHealthReport,
    ProviderReputationReport,
)
from .contracts import WEBHOOK_ROUTES, WebhookRoute
from .control_plane_auth import authorize_command, caller_for_authorization
from .core.providers import get_runtime
from .lead_intake import (
    INTAKE_PRODUCER_CLIENT_ID,
    LeadSubmission,
    accept_lead_submission,
)
from .observability import safe_correlation_id
from .operations import OperationResponse, _operation_json
from .realtime import MemoryRealtimeStore, stream_events
from .runtime_safety import RuntimeSafetyReadback, runtime_safety_readback
from .security import (
    AuthenticationError,
    AuthorizationError,
    RequestValidationError,
    SecurityError,
    authorize_tenant,
)
from .service import (
    CANONICAL_ERROR_SCHEMA,
    EVENT_TYPE_422_RESPONSE,
    IngressError,
    PayloadTooLargeError,
    ReplayConflictError,
    accept_webhook,
)
from .storage import ReplayConflict, StorageError
from .survey_routes import register_survey_routes

router = APIRouter(tags=["appolon-control-plane"])


class TicketConsumeRequest(BaseModel):
    ticket: str = Field(min_length=32, max_length=512)


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
def correlation_id_for(request: Request) -> str:
    assigned = getattr(request.state, "correlation_id", None)
    if isinstance(assigned, str):
        return assigned
    supplied = safe_correlation_id(request.headers.get("X-Correlation-ID"))
    if supplied is not None:
        return supplied
    return str(uuid.uuid4())


def operation_for(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template.startswith("/"):
        return template
    return "unmatched"


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    retryable: bool,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "correlation_id": correlation_id_for(request),
                "retryable": retryable,
                "details": {},
            }
        },
    )


async def read_limited_body(request: Request, maximum: int) -> bytes:
    raw_lengths = request.headers.getlist("Content-Length")
    if len(raw_lengths) > 1:
        raise RequestValidationError("Content-Length must be provided at most once")
    if raw_lengths:
        raw_length = raw_lengths[0]
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise RequestValidationError("Content-Length must contain only digits")
        if len(raw_length) > 20:
            raise RequestValidationError("Content-Length is outside the supported range")
        length = int(raw_length)
        if length > maximum:
            raise PayloadTooLargeError(f"request body exceeds {maximum} bytes")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise PayloadTooLargeError(f"request body exceeds {maximum} bytes")
        body.extend(chunk)
    return bytes(body)


_runtime = get_runtime


def realtime_store(request: Request):
    active = _runtime(request)
    if active.realtime is None:
        if not active.settings.allow_in_memory_storage:
            raise StorageError("realtime store is unavailable")
        active.realtime = MemoryRealtimeStore()
    return active.realtime


async def authorize_realtime(request: Request, scope: str) -> dict[str, object]:
    return await _runtime(request).tokens.verify(
        request.headers.get("Authorization", ""),
        expected_client_id="websocket-gateway",
        required_scope=scope,
    )


def communications_service(request: Request) -> CommunicationsService:
    active = _runtime(request)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    if active.communications is None:
        active.communications = CommunicationsService(
            store=MemoryCommunicationsStore(),
            commands=active.commands,
            umbrella_controls=active.settings.umbrella_controls,
        )
    return active.communications


async def _authorize_communication_read(request: Request) -> str:
    _, _, tenant_id = await authenticated_tenant(request)
    return tenant_id


# ----------------------------------------------------------------------
# Application-level installation (error handlers, OpenAPI). Request
# telemetry and correlation live in the single guard (app.core.request_guard).
# ----------------------------------------------------------------------
def install_error_handlers(app: FastAPI) -> None:
    """The canonical error envelope for every domain error type."""

    @app.exception_handler(SecurityError)
    async def security_error(request: Request, exc: SecurityError) -> JSONResponse:
        telemetry = getattr(request.app.state, "observability", None)
        if telemetry is not None:
            telemetry.record_auth_denial(operation_for(request), exc.code)
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=str(exc),
            retryable=exc.retryable,
        )

    @app.exception_handler(IngressError)
    async def ingress_error(request: Request, exc: IngressError) -> JSONResponse:
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=str(exc),
            retryable=exc.retryable,
        )

    @app.exception_handler(StorageError)
    async def storage_error(request: Request, exc: StorageError) -> JSONResponse:
        return error_response(
            request,
            status_code=503,
            code=exc.code,
            message="required persistence dependency is unavailable",
            retryable=exc.retryable,
        )

    @app.exception_handler(CommandError)
    async def command_error(request: Request, exc: CommandError) -> JSONResponse:
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=str(exc),
            retryable=exc.retryable,
        )

    @app.exception_handler(CommunicationsError)
    async def communications_error(
        request: Request,
        exc: CommunicationsError,
    ) -> JSONResponse:
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=str(exc),
            retryable=exc.retryable,
        )

    @app.exception_handler(FastApiValidationError)
    async def validation_error(
        request: Request,
        exc: FastApiValidationError,
    ) -> JSONResponse:
        # Three published validation contracts coexist on the single
        # application: the control plane answers 400 with the canonical
        # envelope, sales intake answers a sanitized 422, and every other
        # route keeps FastAPI's 422 that the integration contracts document.
        guard = getattr(request.app.state, "request_guard", None)
        path = request.url.path
        if guard is not None and guard.control_plane_route(request.method, path):
            return error_response(
                request,
                status_code=400,
                code="invalid_request",
                message="request does not match the canonical API contract",
                retryable=False,
            )
        if path.startswith("/api/v1/sales/"):
            correlation_id = request.headers.get("X-Correlation-ID", "") or "generated"
            return JSONResponse(
                {
                    "code": "INVALID_LEAD_CANDIDATE",
                    "message": "sales request validation failed",
                    "correlation_id": correlation_id,
                    "retryable": False,
                },
                status_code=422,
                headers={"X-Correlation-ID": correlation_id},
            )
        return await request_validation_exception_handler(request, exc)


def install_canonical_openapi(app: FastAPI) -> None:
    """Document the control plane's 400 envelope in place of FastAPI's 422.

    Only control-plane operations (the handler-authenticated Appolon routers)
    are rewritten; integration routes keep the documented 422.
    """
    generated_openapi = app.openapi

    def canonical_openapi() -> dict:
        schema = generated_openapi()
        guard = getattr(app.state, "request_guard", None)
        automatic_validation = {
            "description": "Validation Error",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/HTTPValidationError"}
                }
            },
        }
        for path, path_item in schema.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if guard is not None and not guard.control_plane_route(method.upper(), path):
                    continue
                responses = operation.get("responses", {})
                if responses.get("422") != automatic_validation:
                    continue
                responses.pop("422")
                invalid = responses.setdefault(
                    "400", {"description": "Invalid canonical request"}
                )
                invalid["content"] = {"application/json": {"schema": CANONICAL_ERROR_SCHEMA}}
        return schema

    setattr(app, "openapi", canonical_openapi)


# ----------------------------------------------------------------------
# Realtime
# ----------------------------------------------------------------------
@router.post("/internal/v1/realtime/tickets/consume", include_in_schema=False)
async def consume_realtime_ticket(body: TicketConsumeRequest, request: Request) -> JSONResponse:
    await authorize_realtime(request, "realtime.ticket.consume")
    principal = await realtime_store(request).consume_ticket(body.ticket, datetime.now(UTC))
    if principal is None:
        raise AuthenticationError("ticket is invalid, expired, or already consumed")
    return JSONResponse(
        content={
            "active": True,
            "tenant_id": principal.tenant_id,
            "campaign_id": principal.campaign_id,
            "agent_id": principal.agent_id,
            "role": principal.role,
            "expires_at": principal.expires_at.astimezone(UTC).isoformat(),
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/internal/v1/realtime/events/stream", include_in_schema=False)
async def realtime_event_stream(
    request: Request,
    tenant_id: str,
    campaign_id: str,
    agent_id: str,
    after: int = Query(0, ge=0),
) -> StreamingResponse:
    claims = await authorize_realtime(request, "realtime.events.read")
    authorize_tenant(claims, tenant_id)
    for claim, requested in (("campaign_id", campaign_id), ("agent_id", agent_id)):
        allowed = claims.get(claim)
        if not isinstance(allowed, str) or allowed != requested or allowed == "*":
            raise AuthorizationError(f"token is not authorized for requested {claim}")
    return StreamingResponse(
        stream_events(
            realtime_store(request),
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            agent_id=agent_id,
            after=after,
            disconnected=request.is_disconnected,
        ),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# ----------------------------------------------------------------------
# Authenticated metrics and safety readback
# ----------------------------------------------------------------------
# The two governed reads authenticate as their very first statement against
# the runtime token verifier; scripts/validate_staging_intake_observability_contract.py
# proves this binding from source.
@router.get("/metrics")
async def metrics(request: Request) -> Response:
    await request.app.state.runtime.tokens.verify(
        request.headers.get("Authorization", ""),
        expected_client_id="monitoring-readonly",
        required_scope="metrics.read",
    )
    active = _runtime(request)
    report = await active.readiness()
    telemetry = request.app.state.observability
    telemetry.record_readiness(report.components)
    await telemetry.refresh_intake_backlog(active.inbox)
    body, media_type = telemetry.render()
    return Response(content=body, headers={"Content-Type": media_type})


@router.get("/v1/runtime/safety", response_model=RuntimeSafetyReadback)
async def runtime_safety(request: Request) -> RuntimeSafetyReadback:
    await request.app.state.runtime.tokens.verify(
        request.headers.get("Authorization", ""),
        expected_client_id="monitoring-readonly",
        required_scope="health.read",
    )
    return RuntimeSafetyReadback.model_validate(
        runtime_safety_readback(_runtime(request).settings)
    )


# ----------------------------------------------------------------------
# Communications
# ----------------------------------------------------------------------
@router.post(
    "/v1/communication/messages",
    response_model=CommunicationMessage,
    responses={202: {"model": CommunicationMessage}},
)
@router.post(
    "/v1/communications/messages",
    response_model=CommunicationMessage,
    responses={202: {"model": CommunicationMessage}},
)
async def create_communication_message(
    body: CreateMessageRequest,
    request: Request,
) -> JSONResponse:
    caller, claims, tenant_id = await authenticated_tenant(request, mutation=True)
    command_type, target, _, _ = CHANNEL_COMMAND[body.channel]
    authorize_command(caller, command_type=command_type, target=target)
    authorization = authorization_header(request)
    correlation_id = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthorizationError("authenticated token subject is required")
    actor = optional_header(request, "X-Codestra-Actor", minimum=1, maximum=300) or subject
    if actor != subject:
        raise AuthorizationError("requested actor must equal token subject")
    message, duplicate = await communications_service(request).submit_message(
        body,
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        actor=actor,
        authorization=authorization,
        token_verifier=_runtime(request).tokens,
    )
    return JSONResponse(
        status_code=200 if duplicate else 202,
        content=message.model_dump(mode="json"),
        headers={"X-Correlation-ID": message.correlationId},
    )


@router.get("/v1/communications/messages/by-idempotency", response_model=CommunicationMessage)
async def get_communication_by_idempotency(request: Request) -> CommunicationMessage:
    caller, _, tenant_id = await authenticated_tenant(request)
    key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    message = await communications_service(request).store.message_by_idempotency(tenant_id, key)
    expected_channel = {"odoo-sms": "sms", "odoo-email": "email"}.get(caller.client_id)
    if expected_channel is not None and message.channel != expected_channel:
        raise CommunicationsNotFound("message was not found")
    return message


@router.get("/v1/communications/messages", response_model=CommunicationMessagePage)
async def list_communication_messages(request: Request) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    service = communications_service(request)
    return JSONResponse(
        status_code=200,
        content=Paged(
            items=[
                item.model_dump(mode="json")
                for item in service.list_messages(
                    tenant_id,
                    channel=request.query_params.get("channel"),
                    status=request.query_params.get("status"),
                )
            ]
        ).model_dump(mode="json"),
    )


@router.get("/v1/communication/messages/{messageId}", response_model=CommunicationMessage)
@router.get("/v1/communications/messages/{messageId}", response_model=CommunicationMessage)
async def get_communication_message(messageId: UUID, request: Request) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    service = communications_service(request)
    message = await service.refresh_command_status(tenant_id, messageId)
    return JSONResponse(status_code=200, content=message.model_dump(mode="json"))


@router.get(
    "/v1/communications/messages/{messageId}/events",
    response_model=CommunicationEventPage,
)
async def list_communication_message_events(messageId: UUID, request: Request) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    service = communications_service(request)
    await service.refresh_command_status(tenant_id, messageId)
    return JSONResponse(
        status_code=200,
        content=Paged(
            items=[
                item.model_dump(mode="json")
                for item in service.message_events(tenant_id, messageId)
            ]
        ).model_dump(mode="json"),
    )


@router.post(
    "/v1/communications/messages/{messageId}/cancel",
    response_model=CommunicationMessage,
    responses={202: {"model": CommunicationMessage}},
)
async def cancel_communication_message(messageId: UUID, request: Request) -> JSONResponse:
    _, claims, tenant_id = await authenticated_tenant(request, mutation=True)
    authorization = authorization_header(request)
    required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthorizationError("authenticated token subject is required")
    actor = optional_header(request, "X-Codestra-Actor", minimum=1, maximum=300) or subject
    if actor != subject:
        raise AuthorizationError("requested actor must equal token subject")
    message, duplicate = await communications_service(request).cancel(
        tenant_id,
        messageId,
        idempotency_key=idempotency_key,
        actor=actor,
        authorization=authorization,
        token_verifier=_runtime(request).tokens,
    )
    return JSONResponse(status_code=200 if duplicate else 202, content=message.model_dump(mode="json"))


@router.get("/v1/communications/provider-health", response_model=ProviderHealthReport)
@router.get("/v1/communications/providers/health", response_model=ProviderHealthReport)
async def get_communication_provider_health(request: Request) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    service = communications_service(request)
    return JSONResponse(status_code=200, content=await service.adapter.health(tenant_id))


@router.get("/v1/communications/reputation", response_model=ProviderReputationReport)
async def get_communication_reputation(request: Request) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    service = communications_service(request)
    return JSONResponse(status_code=200, content=await service.adapter.reputation(tenant_id))


@router.get("/v1/communications/usage", response_model=CommunicationUsageReport)
async def get_communication_usage(
    request: Request,
    from_: AwareDatetime | None = Query(None, alias="from"),
    to: AwareDatetime | None = Query(None),
) -> JSONResponse:
    tenant_id = await _authorize_communication_read(request)
    messages = [
        item
        for item in communications_service(request).list_messages(tenant_id)
        if item.direction == "outbound"
    ]
    return JSONResponse(
        status_code=200,
        content={
            "from": (from_ or datetime.now(UTC)).isoformat(),
            "to": (to or datetime.now(UTC)).isoformat(),
            "totals": [
                {
                    "channel": channel,
                    "accepted": len([item for item in messages if item.channel == channel]),
                    "delivered": len(
                        [
                            item
                            for item in messages
                            if item.channel == channel and item.status == "delivered"
                        ]
                    ),
                    "failed": len(
                        [
                            item
                            for item in messages
                            if item.channel == channel and item.status == "failed"
                        ]
                    ),
                    "suppressed": len(
                        [
                            item
                            for item in messages
                            if item.channel == channel and item.status == "suppressed"
                        ]
                    ),
                }
                for channel in ("email", "sms")
            ],
        },
    )


# ----------------------------------------------------------------------
# Intake
# ----------------------------------------------------------------------
@router.post("/v1/intake/leads")
async def submit_lead(request: Request) -> JSONResponse:
    active = _runtime(request)
    authorization = authorization_header(request)
    claims = await active.tokens.verify(
        authorization,
        expected_client_id=INTAKE_PRODUCER_CLIENT_ID,
        required_scope="leads.write",
    )
    content_type = required_header(request, "Content-Type", minimum=16, maximum=128)
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise RequestValidationError("Content-Type must be application/json")

    tenant_id = required_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    correlation_id = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    authorize_tenant(claims, tenant_id)

    raw = await read_limited_body(request, active.settings.max_request_body_bytes)
    try:
        submission = LeadSubmission.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise RequestValidationError(
            "body does not match the canonical lead intake contract"
        ) from exc
    request.state.intake_metrics = {
        "channel": submission.source,
        "form_kind": "configured" if submission.formId else "generic",
    }
    if submission.tenantId != tenant_id:
        raise RequestValidationError("X-Tenant-ID does not match submission tenantId")

    try:
        result = await accept_lead_submission(
            active,
            submission,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )
    except ReplayConflict as exc:
        raise ReplayConflictError(str(exc)) from exc

    return JSONResponse(
        status_code=200 if result.duplicate else 202,
        content=result.model_dump(mode="json"),
        headers={"X-Correlation-ID": result.correlation_id},
    )


register_survey_routes(router)


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
@router.post(
    "/v1/commands",
    response_model=OperationResponse,
    responses={202: {"model": OperationResponse, "description": "Command accepted"}},
)
async def submit_command(command: CommandEnvelope, request: Request) -> JSONResponse:
    active = _runtime(request)
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    claims = await active.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=caller.command_scope,
    )
    authorize_command(caller, command_type=command.command_type, target=command.target)
    authorize_tenant(claims, command.tenant_id)
    tenant_id = required_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    if tenant_id != command.tenant_id:
        raise RequestValidationError("X-Tenant-ID does not match command tenant")
    correlation_id = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    if correlation_id != command.correlation_id:
        raise RequestValidationError("X-Correlation-ID does not match command correlation_id")
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    if idempotency_key != command.idempotency_key:
        raise RequestValidationError("Idempotency-Key does not match command idempotency_key")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthorizationError("token subject is required for commands")
    if (
        caller.client_id == "n8n-automation"
        and active.settings.umbrella_controls.get("N8N_EXTERNAL_PROVIDER_WRITES") is not True
    ):
        raise CommandCapabilityDisabled("N8N_EXTERNAL_PROVIDER_WRITES is disabled")
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    operation = await active.commands.submit(
        command,
        authenticated_subject=subject,
        authenticated_client_id=caller.client_id,
    )
    return JSONResponse(
        status_code=200 if operation.duplicate else 202,
        content=_operation_json(operation),
        headers={
            "Location": f"/v1/operations/{operation.command_id}",
            "X-Correlation-ID": operation.correlation_id,
        },
    )


# ----------------------------------------------------------------------
# Signed webhook ingress (contract-driven)
# ----------------------------------------------------------------------
def _register_ingress(route: WebhookRoute) -> None:
    async def ingress(request: Request) -> JSONResponse:
        active = _runtime(request)
        headers = {key.lower(): value for key, value in request.headers.items()}
        claims = await active.tokens.verify(
            headers.get("authorization", ""),
            expected_client_id=route.producer_client_id,
            required_scope=route.required_scope,
        )
        raw = await read_limited_body(request, active.settings.max_request_body_bytes)
        result, status_code = await accept_webhook(
            active,
            route,
            claims=claims,
            method=request.method,
            path=request.url.path,
            raw_body=raw,
            headers=headers,
        )
        if (
            route.producer_client_id in {"klyrow-gateway", "telnexa-gateway"}
            and active.communications is not None
        ):
            from .models import EventEnvelope

            envelope = EventEnvelope.model_validate(json.loads(raw))
            await active.communications.record_provider_event(envelope)
        return JSONResponse(status_code=status_code, content=result.model_dump(mode="json"))

    router.add_api_route(
        route.path,
        ingress,
        methods=["POST"],
        name=f"ingress-{route.producer_client_id}-{route.path.rsplit('/', 1)[-1]}",
        responses={422: EVENT_TYPE_422_RESPONSE},
    )


for _webhook_route in WEBHOOK_ROUTES:
    # /api/v1/odoo/events is served by app.webhook_api.odoo_event_router.
    if _webhook_route.path != "/api/v1/odoo/events":
        _register_ingress(_webhook_route)
