from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .contracts import WEBHOOK_ROUTES, WebhookRoute
from .security import RequestValidationError
from .service import EVENT_TYPE_422_RESPONSE, PayloadTooLargeError, accept_webhook

router = APIRouter(tags=["provider-webhooks"])
odoo_event_router = APIRouter(tags=["odoo-events"])


def _connector_key(route: WebhookRoute) -> str:
    value = route.producer_client_id.split("-", 1)[0]
    if not value:
        raise RuntimeError("webhook contract has no connector identity")
    return value


def _endpoint_key(route: WebhookRoute) -> str:
    parts = [part for part in route.path.split("/") if part]
    if not parts:
        raise RuntimeError("webhook contract has no endpoint identity")
    return parts[-1]


def _build_route_indexes() -> tuple[
    dict[tuple[str, str], WebhookRoute],
    dict[str, WebhookRoute],
]:
    by_endpoint: dict[tuple[str, str], WebhookRoute] = {}
    by_connector: dict[str, WebhookRoute] = {}
    for route in WEBHOOK_ROUTES:
        connector = _connector_key(route)
        endpoint = _endpoint_key(route)
        key = (connector, endpoint)
        if key in by_endpoint:
            raise RuntimeError(
                f"duplicate webhook contract for connector={connector} endpoint={endpoint}"
            )
        by_endpoint[key] = route
        by_connector.setdefault(connector, route)
    by_connector["vicidial"] = next(
        route
        for route in WEBHOOK_ROUTES
        if route.producer_client_id == "vicidial-adapter"
    )
    return by_endpoint, by_connector


_BY_CONNECTOR_ENDPOINT, _BY_CONNECTOR = _build_route_indexes()


def route_for_connector_endpoint(
    connector_id: str,
    endpoint_key: str,
) -> WebhookRoute:
    route = _BY_CONNECTOR_ENDPOINT.get((connector_id, endpoint_key))
    if route is None:
        raise RequestValidationError("unknown webhook connector or endpoint")
    return route


async def _body(request: Request) -> bytes:
    maximum = request.app.state.runtime.settings.max_request_body_bytes
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > maximum:
            raise PayloadTooLargeError(f"request body exceeds {maximum} bytes")
        raw.extend(chunk)
    return bytes(raw)


async def _accept(request: Request, route: WebhookRoute):
    headers = {key.lower(): value for key, value in request.headers.items()}
    claims = await request.app.state.runtime.tokens.verify(
        headers.get("authorization", ""),
        expected_client_id=route.producer_client_id,
        required_scope=route.required_scope,
    )
    result, status = await accept_webhook(
        request.app.state.runtime,
        route,
        claims=claims,
        method=request.method,
        path=request.url.path,
        raw_body=await _body(request),
        headers=headers,
    )
    return JSONResponse(
        status_code=status,
        content=result.model_dump(mode="json"),
        headers={"X-Correlation-ID": result.correlation_id},
    )


@odoo_event_router.post(
    "/api/v1/odoo/events",
    operation_id="ingress_odoo_event",
    responses={422: EVENT_TYPE_422_RESPONSE},
)
async def odoo_event(request: Request):
    """Accept the exact Odoo event contract with its bound service identity."""

    route = next(
        item
        for item in WEBHOOK_ROUTES
        if item.path == "/api/v1/odoo/events"
        and item.producer_client_id == "odoo-integration"
        and item.required_scope == "odoo.events.publish"
    )
    return await _accept(request, route)


@router.post(
    "/v1/webhooks/{connector_id}/{endpoint_key}/{webhook_id}",
    responses={422: EVENT_TYPE_422_RESPONSE},
)
async def generic_webhook(
    connector_id: str,
    endpoint_key: str,
    webhook_id: str,
    request: Request,
):
    if not connector_id or not endpoint_key or not webhook_id:
        raise RequestValidationError("unknown webhook connector or endpoint")
    route = route_for_connector_endpoint(connector_id, endpoint_key)
    dynamic = WebhookRoute(
        route.producer_client_id,
        route.required_scope,
        request.url.path,
        route.event_types,
    )
    return await _accept(request, dynamic)


@router.post(
    "/webhooks/vicidial/call-result/{webhook_id}",
    responses={422: EVENT_TYPE_422_RESPONSE},
)
async def vicidial_call_result(webhook_id: str, request: Request):
    if not webhook_id:
        raise RequestValidationError("webhook_id is required")
    base = _BY_CONNECTOR["vicidial"]
    return await _accept(
        request,
        WebhookRoute(
            base.producer_client_id,
            base.required_scope,
            request.url.path,
            base.event_types,
        ),
    )


@router.post("/v1/crm/events/{webhook_id}", responses={422: EVENT_TYPE_422_RESPONSE})
@router.post(
    "/v1/crm/delivery-results/{webhook_id}",
    responses={422: EVENT_TYPE_422_RESPONSE},
)
async def crm_event(webhook_id: str, request: Request):
    if not webhook_id:
        raise RequestValidationError("webhook_id is required")
    base = _BY_CONNECTOR["odoo"]
    return await _accept(
        request,
        WebhookRoute(
            base.producer_client_id,
            base.required_scope,
            request.url.path,
            base.event_types,
        ),
    )
