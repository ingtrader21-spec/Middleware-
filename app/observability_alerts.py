from __future__ import annotations

from .api_inputs import authorization_header, optional_header, required_header
from .core.header_authority import TENANT_ID, CORRELATION_ID, IDEMPOTENCY_KEY

import hashlib
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any, Literal, Mapping

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError as FastApiValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from .commands import CommandError
from .commands import MemoryCommandStore, PostgresCommandStore
from app.core.config import Settings
from .control_plane_auth import caller_for_authorization
from .models import EventEnvelope
from .observability_alert_contract import (
    ALERTMANAGER_CLIENT_ID,
    COMMAND_CAPABILITY,
    DELIVERY_CLIENT_ID,
    IDEMPOTENCY_RE,
    OPERATOR_CLIENT_ID,
    AlertDeliveryEvent,
    AlertPolicy,
    AlertOperationView,
    AlertSubmissionResponse,
    AlertmanagerWebhook,
    activation_enabled,
    load_policy,
    require_alert_operation,
)
from .observability_projection import ObservabilityOdooProjection
from .observability_incidents import (
    AlertmanagerStatusSnapshot,
    IncidentConflict,
    IncidentMutationRequest,
    IncidentService,
    IncidentStore,
    IncidentState,
    MemoryIncidentStore,
    PostgresIncidentStore,
    decode_cursor,
    encode_cursor,
)
from app.core.runtime import RuntimeContainer as Runtime, build_runtime_container as build_runtime
from .security import (
    AuthorizationError,
    RequestValidationError,
    SecurityError,
    authorize_tenant,
)
from .storage import StorageError, canonical_payload_sha256


SOURCE_DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{2,127}$")
NATIVE_RECEIVERS = frozenset(
    {
        "middleware-default",
        "middleware-heartbeat",
        "middleware-critical",
        "middleware-high",
        "middleware-warning",
        "middleware-informational",
    }
)
NATIVE_MAX_ALERTS = 100


async def read_bounded_json(request: Request, *, maximum: int) -> bytes:
    content_type = request.headers.get("Content-Type", "").split(";", 1)[0]
    if content_type.strip().lower() != "application/json":
        raise RequestValidationError("Content-Type must be application/json")
    declared = request.headers.get("Content-Length")
    if declared:
        try:
            if int(declared) > maximum:
                raise RequestValidationError(
                    "request body exceeds the configured limit"
                )
        except ValueError as exc:
            raise RequestValidationError("Content-Length is invalid") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise RequestValidationError("request body exceeds the configured limit")
    if not body:
        raise RequestValidationError("request body is required")
    return bytes(body)


async def authorize(
    request: Request,
    *,
    expected_client_id: str,
    scope_kind: Literal["command", "status"],
    policy: AlertPolicy,
    correlation_fallback: str = "",
) -> tuple[str, str]:
    tenant_id = optional_header(request, TENANT_ID, minimum=1, maximum=128) or ""
    correlation_id = (
        optional_header(request, CORRELATION_ID, minimum=1, maximum=180) or correlation_fallback
    )
    if tenant_id != policy.tenant_id:
        raise AuthorizationError("observability tenant does not match the fixed policy")
    if not correlation_id or len(correlation_id) > 180:
        raise RequestValidationError("X-Correlation-ID is required")
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    if caller.client_id != expected_client_id:
        raise AuthorizationError("caller is not authorized for observability alerts")
    required_scope = (
        caller.command_scope if scope_kind == "command" else caller.status_scope
    )
    claims = await request.app.state.runtime.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=required_scope,
    )
    authorize_tenant(claims, tenant_id)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthorizationError("token subject is required")
    return subject, correlation_id


def source_deployment(request: Request) -> str:
    value = request.headers.get("X-Source-Deployment", "").strip()
    if not SOURCE_DEPLOYMENT_RE.fullmatch(value):
        raise RequestValidationError("X-Source-Deployment is required and malformed")
    return value


def problem(
    error: Exception,
    request: Request,
    status_code: int,
    code: str,
) -> JSONResponse:
    correlation_id = (
        optional_header(request, CORRELATION_ID, minimum=1, maximum=180)
        or getattr(request.state, "correlation_id", "")
    )
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else None
    return JSONResponse(
        status_code=status_code,
        content={
            "code": code,
            "message": str(error),
            "correlation_id": correlation_id,
            "retryable": bool(getattr(error, "retryable", False)),
        },
        headers=headers,
    )


def create_app(
    *,
    settings: Settings | None = None,
    runtime: Runtime | None = None,
    policy: AlertPolicy | None = None,
    env: Mapping[str, str] | None = None,
) -> FastAPI:
    active_settings = settings or Settings.from_env()
    active_policy = policy or load_policy()
    delivery_enabled = activation_enabled(active_settings, env=env)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        active = runtime or await build_runtime(active_settings)
        if active.commands is None:
            raise StorageError("command ledger is unavailable")
        active.commands.policies.capabilities[COMMAND_CAPABILITY] = delivery_enabled
        incident_store: IncidentStore
        if isinstance(active.commands.store, MemoryCommandStore):
            incident_store = MemoryIncidentStore(active.commands)
        elif isinstance(active.commands.store, PostgresCommandStore):
            incident_store = PostgresIncidentStore(active.commands)
        else:
            raise StorageError("incident ledger is unavailable")
        active.incidents = IncidentService(
            store=incident_store,
            commands=active.commands,
            policy=active_policy,
            delivery_enabled=delivery_enabled,
        )
        app.state.odoo_projection = ObservabilityOdooProjection(
            getattr(incident_store, "pool", None)
        )
        app.state.runtime = active
        try:
            yield
        finally:
            if runtime is None:
                await active.close()

    app = FastAPI(
        title="Codestra Middleware Observability Alert API",
        version=active_settings.app_version,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    app.state.metrics = {"ingested": 0, "duplicates": 0, "status_sync": 0}

    async def project_incident(request: Request, incident) -> None:
        projection = request.app.state.odoo_projection
        # Memory-only alert runtimes deliberately have no Odoo queue. Keep
        # local incident behavior usable while production Postgres runtimes
        # fail closed if their durable projection queue is unavailable.
        if not projection.enabled:
            return
        try:
            await projection.enqueue_incident(incident)
        except Exception as exc:
            raise StorageError("observability Odoo projection queue unavailable") from exc

    @app.exception_handler(SecurityError)
    async def security_error(request: Request, exc: SecurityError) -> JSONResponse:
        return problem(exc, request, exc.status_code, exc.code)

    @app.exception_handler(CommandError)
    async def command_error(request: Request, exc: CommandError) -> JSONResponse:
        return problem(exc, request, exc.status_code, exc.code)

    @app.exception_handler(StorageError)
    async def storage_error(request: Request, exc: StorageError) -> JSONResponse:
        return problem(exc, request, 503, exc.code)

    @app.exception_handler(FastApiValidationError)
    async def validation_error(
        request: Request,
        exc: FastApiValidationError,
    ) -> JSONResponse:
        return problem(
            RequestValidationError("request validation failed"),
            request,
            422,
            "validation_failed",
        )

    @app.get("/health")
    @app.get("/platform/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy", "service": "middleware-observability-alerts"}

    @app.head("/health")
    @app.head("/platform/v1/health")
    async def health_head() -> Response:
        return Response(status_code=200)

    @app.get("/readiness")
    @app.get("/platform/v1/readiness")
    async def readiness(request: Request) -> JSONResponse:
        report = await request.app.state.runtime.readiness()
        return JSONResponse(
            status_code=200 if report.ready else 503,
            content={"ready": report.ready, "components": report.components},
        )

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {
            "service": "middleware-observability-alerts",
            "environment": active_settings.app_env,
            "release_id": active_settings.release_id,
            "git_sha": active_settings.source_sha,
            "image_digest": active_settings.image_digest,
            "build_time": active_settings.build_time,
            "schema_version": active_settings.schema_head,
            "configuration_checksum": active_settings.configuration_checksum,
        }

    @app.get("/capabilities")
    async def capabilities() -> dict[str, Any]:
        return {
            "service": "middleware-observability-alerts",
            "default_policy": "DENY",
            "normal_delivery_path": active_policy.normal_delivery_path,
            "direct_smtp_allowed": False,
            COMMAND_CAPABILITY: delivery_enabled,
            "recipient_policy_id": active_policy.recipient_policy_id,
            "sender_policy_id": active_policy.sender_policy_id,
        }

    @app.get("/metrics", response_class=Response)
    async def metrics(request: Request) -> Response:
        values = request.app.state.metrics
        body = "\n".join(
            (
                "# HELP codestra_observability_incident_events_total Durable incident events accepted by kind.",
                "# TYPE codestra_observability_incident_events_total counter",
                f'codestra_observability_incident_events_total{{result="accepted"}} {values["ingested"]}',
                f'codestra_observability_incident_events_total{{result="duplicate"}} {values["duplicates"]}',
                "# HELP codestra_observability_status_sync_total Alertmanager status records accepted.",
                "# TYPE codestra_observability_status_sync_total counter",
                f"codestra_observability_status_sync_total {values['status_sync']}",
                "",
            )
        )
        return Response(content=body, media_type="text/plain; version=0.0.4")

    @app.post("/internal/v1/alerts/alertmanager")
    @app.post("/v1/integrations/alertmanager/events")
    @app.post("/v1/observability/alerts", deprecated=True)
    async def submit_alerts(request: Request) -> JSONResponse:
        native_header = request.headers.get("X-Alertmanager-Native-Webhook", "")
        if native_header not in {"", "v4"}:
            raise RequestValidationError("unsupported native Alertmanager webhook mode")
        native = native_header == "v4"
        if native:
            request.state.correlation_id = (
                optional_header(request, CORRELATION_ID, minimum=1, maximum=180)
                or "alertmanager-native-" + uuid.uuid4().hex
            )
        actor, correlation_id = await authorize(
            request,
            expected_client_id=ALERTMANAGER_CLIENT_ID,
            scope_kind="command",
            policy=active_policy,
            correlation_fallback=getattr(request.state, "correlation_id", "")
            if native
            else "",
        )
        request.state.correlation_id = correlation_id
        supplied_idempotency = optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or ""
        if (supplied_idempotency or not native) and not IDEMPOTENCY_RE.fullmatch(
            supplied_idempotency
        ):
            raise RequestValidationError("Idempotency-Key is required and malformed")
        raw = await read_bounded_json(request, maximum=active_policy.max_body_bytes)
        deployment = source_deployment(request)
        try:
            webhook = AlertmanagerWebhook.model_validate_json(raw)
        except ValidationError as exc:
            raise RequestValidationError("Alertmanager payload is invalid") from exc
        allowed_receivers = {active_policy.receiver}
        if native:
            allowed_receivers.update(NATIVE_RECEIVERS)
        if webhook.receiver not in allowed_receivers:
            raise AuthorizationError("Alertmanager receiver is not approved")
        maximum_alerts = (
            NATIVE_MAX_ALERTS if native else active_policy.max_alerts_per_request
        )
        if len(webhook.alerts) > maximum_alerts:
            raise RequestValidationError("too many alerts in one request")
        if native:
            # Normalize the principal Alertmanager vocabulary at the authenticated
            # boundary. Tenant, workload, scope, metadata and delivery policy
            # checks remain identical to the explicit transport.
            for label_map in [webhook.group_labels, webhook.common_labels] + [
                item.labels for item in webhook.alerts
            ]:
                if label_map.get("severity") == "informational":
                    label_map["severity"] = "info"
            if not supplied_idempotency:
                supplied_idempotency = (
                    "alertmanager-native-v1:"
                    + canonical_payload_sha256(
                        {
                            "tenant_id": active_policy.tenant_id,
                            "source_deployment": deployment,
                            "webhook": webhook.model_dump(mode="json", by_alias=True),
                        }
                    )
                )

        for alert in webhook.alerts:
            if alert.labels["environment"] not in active_policy.allowed_environments:
                raise AuthorizationError("alert environment is not approved")
            if alert.labels["severity"] not in active_policy.allowed_severities:
                raise AuthorizationError("alert severity is not approved")

        operations = []
        failures = []
        for alert in webhook.alerts:
            try:
                result = await request.app.state.runtime.incidents.ingest(
                    group_key=webhook.group_key,
                    alert=alert,
                    actor_id=actor,
                    correlation_id=correlation_id,
                    source_deployment=deployment,
                    request_idempotency_key=supplied_idempotency,
                )
                await project_incident(request, result.incident)
            except (IncidentConflict, CommandError, StorageError) as exc:
                if not native or len(webhook.alerts) == 1:
                    raise
                # Native Alertmanager retries the complete webhook on non-2xx.
                # Report per-alert failure instead so one conflicting transition
                # cannot cause already-persisted siblings to be replayed forever.
                failures.append(
                    {
                        "alert_fingerprint": alert.fingerprint,
                        "code": getattr(exc, "code", exc.__class__.__name__),
                        "retryable": bool(getattr(exc, "retryable", False)),
                    }
                )
                continue
            metric = "duplicates" if result.duplicate else "ingested"
            request.app.state.metrics[metric] += 1
            operation = result.operation
            operations.append(
                {
                    "incident_id": result.incident.incident_id,
                    "operation_id": operation.command_id if operation else None,
                    "alert_fingerprint": alert.fingerprint,
                    "alert_state": alert.status,
                    "operation_state": operation.state if operation else "not_created",
                    "notification_status": result.notification_status,
                    "duplicate": result.duplicate,
                    "status_url": (
                        f"/v1/observability/alerts/{operation.command_id}"
                        if operation
                        else None
                    ),
                    "events_url": (
                        f"/v1/observability/alerts/{operation.command_id}/events"
                        if operation
                        else None
                    ),
                }
            )

        response = AlertSubmissionResponse(
            policy_id=active_policy.policy_id,
            recipient_policy_id=active_policy.recipient_policy_id,
            sender_policy_id=active_policy.sender_policy_id,
            operations=[AlertOperationView.model_validate(item) for item in operations],
        )
        duplicate = bool(operations) and all(item["duplicate"] for item in operations)
        content = response.model_dump(mode="json")
        if native and failures:
            content["failures"] = failures
        return JSONResponse(
            status_code=207 if native and failures else (200 if duplicate else 202),
            content=content,
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/alerts/{operation_id}")
    async def get_alert(operation_id: uuid.UUID, request: Request) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=ALERTMANAGER_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        operation = await request.app.state.runtime.commands.get(
            active_policy.tenant_id,
            operation_id,
        )
        require_alert_operation(operation)
        return JSONResponse(
            content=operation.model_dump(mode="json"),
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/alerts/{operation_id}/events")
    async def get_alert_events(
        operation_id: uuid.UUID,
        request: Request,
    ) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=ALERTMANAGER_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        operation = await request.app.state.runtime.commands.get(
            active_policy.tenant_id,
            operation_id,
        )
        require_alert_operation(operation)
        events = await request.app.state.runtime.commands.list_events(
            active_policy.tenant_id,
            operation_id,
            limit=100,
        )
        return JSONResponse(
            content={"items": [event.model_dump(mode="json") for event in events]},
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.post("/v1/integrations/alertmanager/status-events")
    async def accept_alertmanager_status(request: Request) -> JSONResponse:
        actor, correlation_id = await authorize(
            request,
            expected_client_id=ALERTMANAGER_CLIENT_ID,
            scope_kind="command",
            policy=active_policy,
        )
        supplied_idempotency = optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or ""
        if not IDEMPOTENCY_RE.fullmatch(supplied_idempotency):
            raise RequestValidationError("Idempotency-Key is required and malformed")
        raw = await read_bounded_json(request, maximum=active_policy.max_body_bytes)
        try:
            snapshot = AlertmanagerStatusSnapshot.model_validate_json(raw)
        except ValidationError as exc:
            raise RequestValidationError(
                "Alertmanager status payload is invalid"
            ) from exc
        deployment = source_deployment(request)
        if snapshot.source_deployment != deployment:
            raise RequestValidationError(
                "status sourceDeployment must match X-Source-Deployment"
            )
        items = []
        failures: list[CommandError] = []
        for item in snapshot.items:
            try:
                incident = (
                    await request.app.state.runtime.incidents.store.ingest_status(
                        policy=active_policy,
                        item=item,
                        actor_id=actor,
                        correlation_id=correlation_id,
                        source_deployment=deployment,
                        request_idempotency_key=supplied_idempotency,
                        observed_at=snapshot.observed_at,
                    )
                )
            except CommandError as exc:
                failures.append(exc)
                items.append(
                    {
                        "fingerprint": item.fingerprint,
                        "result_status": "rejected",
                        "code": exc.code,
                        "message": str(exc),
                        "retryable": exc.retryable,
                    }
                )
                continue
            await project_incident(request, incident)
            value = incident.model_dump(mode="json")
            value["result_status"] = "duplicate" if incident.duplicate else "applied"
            items.append(value)
            request.app.state.metrics["status_sync"] += 1
        if len(snapshot.items) == 1 and failures:
            raise failures[0]
        return JSONResponse(
            status_code=207 if failures else 200,
            content={"items": items},
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/incidents")
    async def list_incidents(
        request: Request,
        state: IncidentState | None = Query(default=None),
        severity: str | None = Query(default=None, min_length=1, max_length=64),
        service: str | None = Query(default=None, min_length=1, max_length=128),
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, max_length=512),
    ) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=OPERATOR_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        try:
            position = decode_cursor(cursor)
        except IncidentConflict as exc:
            raise RequestValidationError(str(exc)) from exc
        rows = await request.app.state.runtime.incidents.store.list_incidents(
            active_policy.tenant_id,
            limit=limit + 1,
            position=position,
            state=state,
            severity=severity,
            service=service,
        )
        more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            encode_cursor(page[-1].updated_at, page[-1].incident_id)
            if more and page
            else None
        )
        return JSONResponse(
            content={
                "items": [item.model_dump(mode="json") for item in page],
                "next_cursor": next_cursor,
            },
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/incidents/{incident_id}")
    async def get_incident(
        incident_id: uuid.UUID,
        request: Request,
    ) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=OPERATOR_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        incident = await request.app.state.runtime.incidents.store.get(
            active_policy.tenant_id, incident_id
        )
        return JSONResponse(
            content=incident.model_dump(mode="json"),
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/incidents/{incident_id}/timeline")
    async def get_incident_timeline(
        incident_id: uuid.UUID,
        request: Request,
        limit: int = Query(default=100, ge=1, le=100),
        after_event_id: int | None = Query(default=None, ge=1),
    ) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=OPERATOR_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        rows = await request.app.state.runtime.incidents.store.list_timeline(
            active_policy.tenant_id,
            incident_id,
            limit=limit,
            after_event_id=after_event_id,
        )
        return JSONResponse(
            content={"items": [item.model_dump(mode="json") for item in rows]},
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.get("/v1/observability/incidents/{incident_id}/notification-attempts")
    async def get_incident_notification_attempts(
        incident_id: uuid.UUID,
        request: Request,
        limit: int = Query(default=100, ge=1, le=100),
    ) -> JSONResponse:
        _, correlation_id = await authorize(
            request,
            expected_client_id=OPERATOR_CLIENT_ID,
            scope_kind="status",
            policy=active_policy,
        )
        rows = (
            await request.app.state.runtime.incidents.store.list_notification_attempts(
                active_policy.tenant_id,
                incident_id,
                limit=limit,
            )
        )
        return JSONResponse(
            content={"items": [item.model_dump(mode="json") for item in rows]},
            headers={"X-Correlation-ID": correlation_id},
        )

    async def mutate_incident(
        incident_id: uuid.UUID,
        request: Request,
        action: Literal["acknowledge", "resolve", "reopen"],
    ) -> JSONResponse:
        actor, correlation_id = await authorize(
            request,
            expected_client_id=OPERATOR_CLIENT_ID,
            scope_kind="command",
            policy=active_policy,
        )
        supplied_idempotency = optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or ""
        if not IDEMPOTENCY_RE.fullmatch(supplied_idempotency):
            raise RequestValidationError("Idempotency-Key is required and malformed")
        raw = await read_bounded_json(request, maximum=16_384)
        try:
            mutation = IncidentMutationRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise RequestValidationError("incident mutation is invalid") from exc
        incident = await request.app.state.runtime.incidents.store.mutate(
            active_policy.tenant_id,
            incident_id,
            action=action,
            actor_id=actor,
            correlation_id=correlation_id,
            idempotency_key=supplied_idempotency,
            expected_version=mutation.expected_version,
            reason=mutation.reason,
        )
        await project_incident(request, incident)
        return JSONResponse(
            content=incident.model_dump(mode="json"),
            headers={"X-Correlation-ID": correlation_id},
        )

    @app.post("/v1/observability/incidents/{incident_id}/acknowledge")
    async def acknowledge_incident(
        incident_id: uuid.UUID, request: Request
    ) -> JSONResponse:
        return await mutate_incident(incident_id, request, "acknowledge")

    @app.post("/v1/observability/incidents/{incident_id}/resolve")
    async def resolve_incident(
        incident_id: uuid.UUID, request: Request
    ) -> JSONResponse:
        return await mutate_incident(incident_id, request, "resolve")

    @app.post("/v1/observability/incidents/{incident_id}/reopen")
    async def reopen_incident(incident_id: uuid.UUID, request: Request) -> JSONResponse:
        return await mutate_incident(incident_id, request, "reopen")

    @app.post("/v1/observability/alert-delivery-events")
    async def accept_delivery_event(request: Request) -> JSONResponse:
        actor, correlation_id = await authorize(
            request,
            expected_client_id=DELIVERY_CLIENT_ID,
            scope_kind="command",
            policy=active_policy,
        )
        supplied_idempotency = optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or ""
        if not IDEMPOTENCY_RE.fullmatch(supplied_idempotency):
            raise RequestValidationError("Idempotency-Key is required and malformed")
        raw = await read_bounded_json(request, maximum=65_536)
        try:
            event = AlertDeliveryEvent.model_validate_json(raw)
        except ValidationError as exc:
            raise RequestValidationError("alert delivery event is invalid") from exc
        operation = await request.app.state.runtime.commands.get(
            active_policy.tenant_id,
            event.operation_id,
        )
        require_alert_operation(operation)
        if supplied_idempotency != event.event_id:
            raise RequestValidationError(
                "Idempotency-Key must equal the delivery event_id"
            )
        envelope = EventEnvelope(
            event_id=event.event_id,
            event_type="codestra.observability.alert_delivery.v1",
            event_version="1.0",
            occurred_at=event.occurred_at,
            received_at=event.occurred_at,
            source=DELIVERY_CLIENT_ID,
            tenant_id=active_policy.tenant_id,
            correlation_id=operation.correlation_id,
            causation_id=str(event.operation_id),
            idempotency_key=event.event_id,
            payload={**event.model_dump(mode="json"), "actor": actor},
            metadata={
                "recipient_policy_id": active_policy.recipient_policy_id,
                "sender_policy_id": active_policy.sender_policy_id,
            },
        )
        semantic = canonical_payload_sha256(envelope.model_dump(mode="json"))
        result = await request.app.state.runtime.inbox.accept(
            envelope,
            producer_client_id=DELIVERY_CLIENT_ID,
            body_sha256=hashlib.sha256(raw).hexdigest(),
            semantic_sha256=semantic,
        )
        return JSONResponse(
            status_code=200 if result.duplicate else 202,
            content={
                **result.model_dump(mode="json"),
                "operation_id": str(event.operation_id),
                "authoritative_completion": "provider-readback",
            },
            headers={"X-Correlation-ID": correlation_id},
        )

    return app
