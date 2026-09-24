"""FastAPI application for the Codestra Connector Runtime v1."""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import UUID, uuid4

import structlog
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import text

from middleware.connector_sdk import ConnectorCatalogService, ConnectorRegistry
from middleware.connector_sdk.errors import ConnectorError, ManifestValidationError

from .auth import Principal, require_scopes
from .config import RuntimeSettings, get_settings
from .crypto import EncryptedBodyStore
from .cursor import CursorCodec
from .database import Database
from .problems import ProblemError, install_problem_handlers, problem_response
from .repository import ConnectorRepository, IdempotentReplay, _etag_version
from .schemas import (
    ConnectionCreateRequest,
    ConnectorInstallRequest,
    ConnectorUpgradeRequest,
    ManifestValidationRequest,
    WebhookCreateRequest,
    WebhookRotateRequest,
    WebhookUpdateRequest,
)
from .webhook_ingress import (
    EnvironmentSecretResolver,
    WebhookIngressService,
    read_limited_body,
)

_CORRELATION = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _meta(correlation_id: UUID) -> dict[str, str]:
    return {"correlation_id": str(correlation_id), "api_version": "v1"}


def _idempotency(value: str | None) -> str:
    if value is None or not 8 <= len(value) <= 180:
        raise ProblemError(
            status=400,
            code="IDEMPOTENCY_KEY_INVALID",
            title="Invalid idempotency key",
            detail="Idempotency-Key must contain 8 to 180 characters.",
        )
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ProblemError(
            status=400,
            code="IDEMPOTENCY_KEY_INVALID",
            title="Invalid idempotency key",
            detail="Idempotency-Key contains unsupported characters.",
        )
    return value


def _correlation(request: Request) -> UUID:
    return UUID(str(request.state.correlation_id))


def _request_id(request: Request) -> str | None:
    value = request.headers.get("X-Request-ID")
    return value[:180] if value else None


def _traceparent(request: Request) -> str | None:
    value = request.headers.get("traceparent")
    return value[:256] if value else None


def _response(
    *,
    status: int,
    body: dict[str, Any],
    correlation_id: UUID,
    etag: int | None = None,
) -> JSONResponse:
    headers = {
        "Cache-Control": "no-store",
        "X-Correlation-ID": str(correlation_id),
    }
    if etag is not None:
        headers["ETag"] = f'"v{etag}"'
    return JSONResponse(
        status_code=status,
        content=jsonable_encoder(body),
        headers=headers,
    )


def _operation_result(
    result: IdempotentReplay | tuple[int, dict[str, Any]],
    correlation_id: UUID,
) -> JSONResponse:
    if isinstance(result, IdempotentReplay):
        return _response(
            status=result.status,
            body=result.body,
            correlation_id=correlation_id,
        )
    status, body = result
    resource_version = body.get("data", {}).get("resource_version")
    return _response(
        status=status,
        body=body,
        correlation_id=correlation_id,
        etag=int(resource_version) if resource_version is not None else None,
    )


def _settings(request: Request) -> RuntimeSettings:
    return request.app.state.settings


def _repo(request: Request) -> ConnectorRepository:
    return request.app.state.repository


def _cursor(request: Request) -> CursorCodec:
    return request.app.state.cursor_codec


def _load_combined_registry(request: Request) -> ConnectorRegistry:
    registry = ConnectorRegistry()
    with request.app.state.database.session() as session:
        rows = session.execute(
            text(
                """
                SELECT m.manifest
                  FROM connector_sdk.connector_installations i
                  JOIN connector_sdk.connector_manifests m
                    ON m.connector_id=i.connector_id
                   AND m.version=i.current_version
                   AND m.manifest_digest=i.current_manifest_digest
                 WHERE i.environment=:environment
                """
            ),
            {"environment": _settings(request).environment},
        ).scalars().all()
    for raw in rows:
        registry.register_manifest(dict(raw))
    return registry


def _validate_candidate(request: Request, raw: dict[str, Any]) -> dict[str, Any]:
    registry = _load_combined_registry(request)
    try:
        return ConnectorCatalogService(registry).validate_candidate(raw)
    except ManifestValidationError as error:
        raise ProblemError(
            status=422,
            code="MANIFEST_INVALID",
            title="Connector manifest invalid",
            detail="The connector manifest violates the v1 contract.",
            extensions={"errors": list(error.errors)},
        ) from error
    except ConnectorError as error:
        raise ProblemError(
            status=409,
            code="CONNECTOR_REGISTRY_CONFLICT",
            title="Connector registry conflict",
            detail=str(error),
        ) from error


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger = structlog.get_logger(settings.service_name)
    database = Database.create(settings)
    repository = ConnectorRepository(database, settings)
    cursor_codec = CursorCodec(
        settings.cursor_hmac_key.get_secret_value().encode("utf-8")
    )
    body_store = EncryptedBodyStore.from_key_file(
        settings.webhook_body_root,
        settings.body_encryption_key_file,
    )
    app.state.settings = settings
    app.state.logger = logger
    app.state.database = database
    app.state.repository = repository
    app.state.cursor_codec = cursor_codec
    app.state.webhook_ingress = WebhookIngressService(
        repository=repository,
        settings=settings,
        body_store=body_store,
        secrets=EnvironmentSecretResolver(),
    )
    initial_reconciliation = (
        app.state.webhook_ingress.reconcile_pending_bodies()
    )
    logger.info(
        "encrypted_webhook_body_reconciliation_completed",
        **initial_reconciliation,
    )
    try:
        yield
    finally:
        database.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Codestra Connector Runtime API",
        version="1.0.0",
        openapi_version="3.1.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    install_problem_handlers(app)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        candidate = request.headers.get("X-Correlation-ID", "")
        correlation_id = (
            UUID(candidate)
            if candidate and _CORRELATION.fullmatch(candidate)
            else uuid4()
        )
        request.state.correlation_id = correlation_id
        path_parts = request.url.path.strip("/").split("/")
        public_webhook = (
            len(path_parts) == 5
            and path_parts[:2] == ["v1", "webhooks"]
        )
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path.startswith("/v1/")
            and not public_webhook
        ):
            try:
                body = await read_limited_body(
                    request,
                    maximum_bytes=_settings(request).maximum_management_body_bytes,
                    error_code="MANAGEMENT_BODY_TOO_LARGE",
                    error_title="Management request body too large",
                    error_detail="The request body exceeds the management API limit.",
                )
                setattr(request, "_body", body)
            except ProblemError as error:
                return problem_response(request, error)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = str(correlation_id)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz", include_in_schema=False)
    async def health(request: Request):
        settings = _settings(request)
        return {
            "data": {
                "status": "ok",
                "service": settings.service_name,
                "release_sha": settings.release_sha,
                "checks": {},
            },
            "meta": _meta(_correlation(request)),
        }

    @app.get("/readyz", include_in_schema=False)
    async def readiness(request: Request):
        settings = _settings(request)
        checks: dict[str, str] = {}
        ready = True
        try:
            request.app.state.database.ping()
            checks["database"] = "pass"
        except Exception:
            checks["database"] = "fail"
            ready = False
        try:
            migration = request.app.state.database.migration_head()
            checks["migration"] = str(migration or "missing")
            if migration != settings.readiness_requires_migration:
                ready = False
        except Exception:
            checks["migration"] = "fail"
            ready = False
        if not settings.body_encryption_key_file.is_file():
            checks["body_encryption_key"] = "fail"
            ready = False
        else:
            checks["body_encryption_key"] = "pass"
        reconciliation = (
            request.app.state.webhook_ingress.reconcile_pending_bodies()
        )
        if reconciliation["deferred"] or reconciliation["invalid"]:
            checks["body_reconciliation"] = "fail"
            ready = False
        else:
            checks["body_reconciliation"] = "pass"
        status = 200 if ready else 503
        return _response(
            status=status,
            body={
                "data": {
                    "status": "ok" if ready else "not_ready",
                    "service": settings.service_name,
                    "release_sha": settings.release_sha,
                    "checks": checks,
                },
                "meta": _meta(_correlation(request)),
            },
            correlation_id=_correlation(request),
        )

    @app.get("/version", include_in_schema=False)
    async def version(request: Request):
        settings = _settings(request)
        return {
            "data": {
                "service": settings.service_name,
                "api_version": "1.0.0",
                "release_sha": settings.release_sha,
            },
            "meta": _meta(_correlation(request)),
        }

    @app.get("/v1/connectors")
    async def list_connectors(
        request: Request,
        principal: Annotated[Principal, Depends(require_scopes("connector.catalog.read"))],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: str | None = None,
    ):
        del principal
        decoded = _cursor(request).decode(cursor)
        after = str(decoded["after"]) if decoded else None
        rows = _repo(request).list_connectors(limit=limit + 1, after=after)
        more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            _cursor(request).encode({"after": page[-1]["connector_id"]})
            if more and page
            else None
        )
        return {
            "data": page,
            "meta": _meta(_correlation(request)),
            "next_cursor": next_cursor,
        }

    @app.post("/v1/connectors/validate")
    async def validate_connector(
        request: Request,
        payload: ManifestValidationRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.manifest.validate"))],
    ):
        del principal
        result = _validate_candidate(request, payload.manifest)
        return {"data": result, "meta": _meta(_correlation(request))}

    @app.post("/v1/connectors/install")
    async def install_connector(
        request: Request,
        payload: ConnectorInstallRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.install.request"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        settings = _settings(request)
        if not settings.connector_install_enabled:
            raise ProblemError(
                status=403,
                code="CAPABILITY_DISABLED",
                title="Connector installation disabled",
                detail="Connector installation is disabled by runtime policy.",
            )
        _validate_candidate(request, payload.manifest)
        tenant_id = principal.require_tenant()
        result = _repo(request).install_disabled(
            tenant_id=tenant_id,
            manifest_raw=payload.manifest,
            expected_digest=payload.expected_manifest_digest,
            idempotency_key=_idempotency(idempotency_key),
            actor_subject=principal.subject,
            correlation_id=_correlation(request),
            request_id=_request_id(request),
            traceparent=_traceparent(request),
        )
        return _operation_result(result, _correlation(request))

    @app.get("/v1/connectors/{connector_id}")
    async def get_connector(
        request: Request,
        connector_id: str,
        principal: Annotated[Principal, Depends(require_scopes("connector.catalog.read"))],
    ):
        del principal
        row = _repo(request).get_connector(connector_id)
        version = int(row.pop("resource_version"))
        row.pop("manifest", None)
        return _response(
            status=200,
            body={"data": row, "meta": _meta(_correlation(request))},
            correlation_id=_correlation(request),
            etag=version,
        )

    @app.get("/v1/connectors/{connector_id}/manifest")
    async def get_connector_manifest(
        request: Request,
        connector_id: str,
        principal: Annotated[Principal, Depends(require_scopes("connector.manifest.read"))],
    ):
        del principal
        row = _repo(request).get_connector(connector_id)
        return {
            "data": {
                "manifest": row["manifest"],
                "manifest_digest": row["manifest_digest"],
            },
            "meta": _meta(_correlation(request)),
        }

    @app.post("/v1/connectors/{connector_id}/test")
    async def test_connector(
        request: Request,
        connector_id: str,
        principal: Annotated[Principal, Depends(require_scopes("connector.connection.test"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        del principal, idempotency_key
        _repo(request).get_connector(connector_id)
        raise ProblemError(
            status=409,
            code="ADAPTER_NOT_BOUND",
            title="Connector adapter not bound",
            detail="The trusted adapter must be installed before connection testing.",
        )

    @app.post("/v1/connectors/{connector_id}/upgrade")
    async def upgrade_connector(
        request: Request,
        connector_id: str,
        payload: ConnectorUpgradeRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.upgrade.request"))],
    ):
        del connector_id, payload, principal
        if not _settings(request).connector_upgrade_enabled:
            raise ProblemError(
                status=403,
                code="CAPABILITY_DISABLED",
                title="Connector upgrade disabled",
                detail="Connector upgrade is disabled by runtime policy.",
            )
        raise ProblemError(
            status=501,
            code="UPGRADE_WORKFLOW_REQUIRED",
            title="Protected upgrade workflow required",
            detail="Upgrades are executed through the protected release workflow.",
        )

    @app.post("/v1/connectors/{connector_id}/disable")
    async def disable_connector(
        request: Request,
        connector_id: str,
        principal: Annotated[Principal, Depends(require_scopes("connector.disable.request"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ):
        if not _settings(request).connector_disable_enabled:
            raise ProblemError(
                status=403,
                code="CAPABILITY_DISABLED",
                title="Connector disablement disabled",
                detail="Connector disablement is disabled by runtime policy.",
            )
        result = _repo(request).disable_connector(
            tenant_id=principal.require_tenant(),
            connector_id=connector_id,
            expected_version=_etag_version(if_match),
            idempotency_key=_idempotency(idempotency_key),
            actor_subject=principal.subject,
            correlation_id=_correlation(request),
            request_id=_request_id(request),
        )
        return _operation_result(result, _correlation(request))

    @app.get("/v1/connectors/{connector_id}/health")
    async def connector_health(
        request: Request,
        connector_id: str,
        principal: Annotated[Principal, Depends(require_scopes("connector.health.read"))],
    ):
        del principal
        row = _repo(request).get_connector(connector_id)
        return {
            "data": {
                "connector_id": connector_id,
                "state": row["state"],
                "runtime_binding_status": row["runtime_binding_status"],
                "status": "not_bound" if row["runtime_binding_status"] != "VERIFIED" else "unknown",
            },
            "meta": _meta(_correlation(request)),
        }

    @app.post("/v1/integrations/connections")
    async def create_connection(
        request: Request,
        payload: ConnectionCreateRequest,
        principal: Annotated[Principal, Depends(require_scopes("integration.connection.write"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        result = _repo(request).create_connection(
            tenant_id=principal.require_tenant(),
            connector_id=payload.connector_id,
            external_account_reference=payload.external_account_reference,
            configuration=payload.configuration,
            secret_references=payload.secret_references,
            idempotency_key=_idempotency(idempotency_key),
            actor_subject=principal.subject,
            correlation_id=_correlation(request),
            request_id=_request_id(request),
        )
        return _operation_result(result, _correlation(request))

    @app.get("/v1/integrations/connections/{connection_id}")
    async def get_connection(
        request: Request,
        connection_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("integration.connection.read"))],
    ):
        row = _repo(request).get_connection(
            tenant_id=principal.require_tenant(),
            connection_id=connection_id,
        )
        return _response(
            status=200,
            body={"data": row, "meta": _meta(_correlation(request))},
            correlation_id=_correlation(request),
            etag=int(row["resource_version"]),
        )

    @app.get("/v1/integrations/connections/{connection_id}/webhooks")
    async def list_webhooks(
        request: Request,
        connection_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.read"))],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: str | None = None,
    ):
        decoded = _cursor(request).decode(cursor)
        rows = _repo(request).list_webhooks(
            tenant_id=principal.require_tenant(),
            connection_id=connection_id,
            limit=limit + 1,
            after=str(decoded["after"]) if decoded else None,
        )
        more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            _cursor(request).encode({"after": str(page[-1]["webhook_id"])})
            if more and page
            else None
        )
        return {"data": page, "meta": _meta(_correlation(request)), "next_cursor": next_cursor}

    @app.post("/v1/integrations/connections/{connection_id}/webhooks")
    async def create_webhook(
        request: Request,
        connection_id: UUID,
        payload: WebhookCreateRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.write"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        result = _repo(request).create_webhook(
            tenant_id=principal.require_tenant(),
            connection_id=connection_id,
            endpoint_key=payload.endpoint_key,
            secret_reference_current=payload.secret_reference_current,
            idempotency_key=_idempotency(idempotency_key),
            actor_subject=principal.subject,
            correlation_id=_correlation(request),
            request_id=_request_id(request),
        )
        return _operation_result(result, _correlation(request))

    @app.get("/v1/webhooks/{webhook_id}")
    async def get_webhook(
        request: Request,
        webhook_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.read"))],
    ):
        row = _repo(request).get_webhook(
            tenant_id=principal.require_tenant(),
            webhook_id=webhook_id,
        )
        return _response(
            status=200,
            body={"data": row, "meta": _meta(_correlation(request))},
            correlation_id=_correlation(request),
            etag=int(row["resource_version"]),
        )

    @app.patch("/v1/webhooks/{webhook_id}")
    async def update_webhook(
        request: Request,
        webhook_id: UUID,
        payload: WebhookUpdateRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.write"))],
    ):
        del request, webhook_id, payload, principal
        raise ProblemError(
            status=501,
            code="WEBHOOK_UPDATE_WORKFLOW_REQUIRED",
            title="Protected webhook update required",
            detail="Webhook state changes use the protected release workflow.",
        )

    @app.delete("/v1/webhooks/{webhook_id}")
    async def delete_webhook(
        request: Request,
        webhook_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.write"))],
    ):
        del request, webhook_id, principal
        raise ProblemError(
            status=501,
            code="WEBHOOK_DISABLE_WORKFLOW_REQUIRED",
            title="Protected webhook disablement required",
            detail="Webhook disablement uses the protected release workflow.",
        )

    @app.post("/v1/webhooks/{webhook_id}/rotate-secret")
    async def rotate_webhook_secret(
        request: Request,
        webhook_id: UUID,
        payload: WebhookRotateRequest,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.rotate"))],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ):
        if not _settings(request).webhook_secret_rotation_enabled:
            raise ProblemError(
                status=403,
                code="CAPABILITY_DISABLED",
                title="Secret rotation disabled",
                detail="Webhook secret rotation is disabled by runtime policy.",
            )
        result = _repo(request).rotate_webhook_secret(
            tenant_id=principal.require_tenant(),
            webhook_id=webhook_id,
            expected_version=_etag_version(if_match),
            new_secret_reference=payload.new_secret_reference,
            overlap_seconds=payload.overlap_seconds,
            idempotency_key=_idempotency(idempotency_key),
            actor_subject=principal.subject,
            correlation_id=_correlation(request),
            request_id=_request_id(request),
        )
        return _operation_result(result, _correlation(request))

    @app.get("/v1/webhooks/{webhook_id}/deliveries")
    async def list_webhook_deliveries(
        request: Request,
        webhook_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.delivery.read"))],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: str | None = None,
    ):
        decoded = _cursor(request).decode(cursor)
        rows = _repo(request).list_deliveries(
            tenant_id=principal.require_tenant(),
            webhook_id=webhook_id,
            limit=limit + 1,
            after=str(decoded["after"]) if decoded else None,
        )
        more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            _cursor(request).encode({"after": str(page[-1]["inbox_id"])})
            if more and page
            else None
        )
        return {"data": page, "meta": _meta(_correlation(request)), "next_cursor": next_cursor}

    @app.post("/v1/webhook-deliveries/{delivery_id}/replay-request")
    async def request_delivery_replay(
        request: Request,
        delivery_id: UUID,
        principal: Annotated[Principal, Depends(require_scopes("connector.webhook.replay.request"))],
    ):
        del delivery_id, principal
        if not _settings(request).webhook_replay_request_enabled:
            raise ProblemError(
                status=403,
                code="CAPABILITY_DISABLED",
                title="Webhook replay disabled",
                detail="Webhook replay requests are disabled by runtime policy.",
            )
        raise ProblemError(
            status=501,
            code="REPLAY_APPROVAL_REQUIRED",
            title="Protected replay approval required",
            detail="Replay requires a separate approval and dead-letter workflow.",
        )

    @app.post("/v1/webhooks/{connector_id}/{endpoint_key}/{webhook_id}")
    async def connector_webhook_ingress(
        request: Request,
        connector_id: str,
        endpoint_key: str,
        webhook_id: UUID,
    ):
        status, body = await request.app.state.webhook_ingress.accept(
            request,
            connector_id=connector_id,
            endpoint_key=endpoint_key,
            webhook_id=webhook_id,
        )
        return _response(
            status=status,
            body=body,
            correlation_id=_correlation(request),
        )

    return app


app = create_app()
