"""The single router registry of the Middleware application.

Every HTTP surface is declared here as an explicit, ordered group; the
application factory (:mod:`app.application`) mounts groups, never individual
routers, and :func:`assert_unique_routes` refuses an application whose route
table contains the same ``(method, path)`` twice (FastAPI would otherwise
silently serve the first registration and shadow the rest).

Groups
------
``CANONICAL_ROUTERS``
    Contract-backed routes served by every Middleware application.
``COMMON_ROUTERS``
    Routes both deployed profiles serve (campaign design, provider event
    ingress for Klyrow and Telnexa).
``INTEGRATION_ROUTERS``
    The authenticated integration/control surface that the deployed
    ``middleware-integration-api`` process serves.
``APPOLON_ROUTERS``
    The Appolon control plane (inbox/outbox, commands, communications,
    signed webhook ingress) that the production canary serves.
``MONOLITH_ROUTERS``
    Routes only the in-process monolith (``app.main:app``) serves: surfaces
    owned by other deployed processes (the event gateway's VICIdial ingress,
    the AI/recording/social services) plus the legacy TEST_SYN control-plane
    event aliases.
``LEGACY_MONOLITH_ONLY_ROUTERS``
    Deprecated aliases the edge contract classifies as ``denied``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from app.api.internal.ai_jobs import router as internal_ai_jobs_router
from app.api.internal.database import router as internal_database_router
from app.api.internal.klyrow_events import router as klyrow_events_router
from app.api.internal.klyrow_mail import router as klyrow_mail_router
from app.api.internal.telnexa_events import router as telnexa_events_router
from app.api.v1.activity import router as activity_router
from app.api.v1.agent_provisioning import router as agent_provisioning_router
from app.api.v1.agent_provisioning_reads import (
    router as agent_provisioning_reads_router,
)
from app.api.v1.agent_realtime import router as agent_realtime_router
from app.api.v1.ai import router as ai_router
from app.api.v1.ai_commands import router as ai_commands_router
from app.api.v1.ai_console import router as ai_console_router
from app.api.v1.automation import router as automation_router
from app.api.v1.booking import router as booking_router
from app.api.v1.callbacks import router as callbacks_router
from app.api.v1.calls import router as calls_router
from app.api.v1.campaign_search import router as campaign_search_router
from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.commands import router as commands_router
from app.api.v1.contacts import router as contacts_router
from app.api.v1.control import legacy_events_router as control_legacy_events_router
from app.api.v1.control import router as control_router
from app.api.v1.events import router as events_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.lead_automation import router as lead_automation_router
from app.api.v1.lead_reconciliation import router as lead_reconciliation_router
from app.api.v1.mappings import router as mappings_router
from app.api.v1.mcr_odoo_handoff import router as mcr_odoo_handoff_router
from app.api.v1.n8n_runtime import router as n8n_runtime_router
from app.api.v1.n8n_staging import router as n8n_staging_router
from app.api.v1.n8n_target import router as n8n_target_router
from app.api.v1.n8n_transport import router as n8n_transport_router
from app.api.v1.observability_sync import router as observability_sync_router
from app.api.v1.opportunities import router as opportunities_router
from app.api.v1.operations import router as operations_router
from app.api.v1.orchestration import router as orchestration_router
from app.api.v1.orders import router as orders_router
from app.api.v1.platform import router as platform_router
from app.api.v1.presence import router as presence_router
from app.api.v1.provider_commands import router as provider_commands_router
from app.api.v1.provider_webhooks import router as provider_webhooks_router
from app.api.v1.publisher import router as publisher_router
from app.api.v1.quarantine import router as quarantine_router
from app.api.v1.queues import router as queues_router
from app.api.v1.recordings import router as recordings_router
from app.api.v1.registry import router as registry_router
from app.api.v1.reports import router as reports_router
from app.api.v1.sales import router as sales_router
from app.api.v1.service_identity import router as recording_identity_router
from app.api.v1.session_context import router as session_context_router
from app.api.v1.social import router as social_router
from app.api.v1.telephony import router as telephony_router
from app.api.v1.tenants import router as tenants_router
from app.api.v1.tickets import router as tickets_router
from app.api.v1.tts import router as tts_router
from app.api.v1.webphone import router as webphone_router
from app.appolon_routes import router as appolon_control_plane_router
from app.automation_v2 import v2_router as automation_v2_router
from app.campaign_design_api import router as campaign_design_router
from app.commands import CommandError
from app.communications import CommunicationsError
from app.compatibility_api import router as compatibility_api_router
from app.control_api import router as control_api_router
from app.domain_api import legacy_n8n_router as domain_legacy_n8n_router
from app.domain_api import router as domain_api_router
from app.email_production_control import router as email_production_router
from app.integrations.postiz.routes import router as postiz_router
from app.monitoring.routes import router as monitoring_router
from app.n8n_control_plane import router as n8n_control_plane_router
from app.operations import router as appolon_operations_router
from app.platform.api import router as platform_kernel_router
from app.operations_dashboard import router as operations_dashboard_router
from app import provider_control_api as _provider_control_api  # noqa: F401  (registers control routes)
from app.security import SecurityError
from app.service import IngressError
from app.storage import StorageError
from app.webhook_api import odoo_event_router
from app.webhook_api import router as webhook_api_router


class DuplicateRouteError(RuntimeError):
    """The same (method, path) is registered more than once."""


CANONICAL_ROUTERS: tuple[APIRouter, ...] = (
    # Private read-only database operational evidence; explicit auth,
    # edge-denied under /internal/*, and shared by every profile.
    internal_database_router,
    # The V3 command kernel: the six /platform/v1 kernel routes, on every profile.
    platform_kernel_router,
    automation_v2_router,
    automation_router,
    callbacks_router,
    email_production_router,
    agent_provisioning_router,
    agent_provisioning_reads_router,
    session_context_router,
    calls_router,
    activity_router,
    presence_router,
    queues_router,
    contacts_router,
    opportunities_router,
    tickets_router,
    tenants_router,
    campaigns_router,
    monitoring_router,
    observability_sync_router,
    integrations_router,
    odoo_event_router,
    mcr_odoo_handoff_router,
)

# Served by both deployed profiles (integration API and control-plane canary).
COMMON_ROUTERS: tuple[APIRouter, ...] = (
    campaign_design_router,
    klyrow_events_router,
    telnexa_events_router,
)

INTEGRATION_ROUTERS: tuple[APIRouter, ...] = (
    commands_router,
    control_router,
    reports_router,
    operations_router,
    lead_reconciliation_router,
    lead_automation_router,
    orchestration_router,
    provider_webhooks_router,
    mappings_router,
    webphone_router,
    n8n_staging_router,
    n8n_transport_router,
    n8n_runtime_router,
    quarantine_router,
    telephony_router,
    sales_router,
    booking_router,
    platform_router,
)

APPOLON_ROUTERS: tuple[APIRouter, ...] = (
    operations_dashboard_router,
    appolon_operations_router,
    control_api_router,
    compatibility_api_router,
    domain_api_router,
    webhook_api_router,
    appolon_control_plane_router,
)

MONOLITH_ROUTERS: tuple[APIRouter, ...] = (
    events_router,
    control_legacy_events_router,
    publisher_router,
    agent_realtime_router,
    n8n_target_router,
    internal_ai_jobs_router,
    klyrow_mail_router,
    ai_console_router,
    tts_router,
    ai_commands_router,
    orders_router,
    ai_router,
    provider_commands_router,
    postiz_router,
    campaign_search_router,
    registry_router,
    recordings_router,
    recording_identity_router,
    social_router,
)

# Deprecated routers that exist only on the in-process monolith. The canonical
# edge contract classifies their paths as ``denied``: Kong and Caddy answer 404,
# and the deployed application never mounts them (the release endpoint audit
# fails if a denied path is mounted there). They stay on the monolith until
# their published sunset so existing in-process callers keep receiving
# Deprecation/Sunset/Link metadata; new use is prohibited.
LEGACY_MONOLITH_ONLY_ROUTERS: tuple[APIRouter, ...] = (
    n8n_control_plane_router,
    domain_legacy_n8n_router,
)


def install_domain_error_handler(app: FastAPI) -> None:
    """The canonical error envelope for domain errors (no observability hook)."""

    async def domain_error(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = (
            getattr(request.state, "correlation_id", None)
            or request.headers.get("X-Correlation-ID")
            or str(uuid4())
        )
        status_code = int(getattr(exc, "status_code", 500))
        code = str(getattr(exc, "code", "internal_error"))
        retryable = bool(getattr(exc, "retryable", status_code >= 500))
        message = (
            "required persistence dependency is unavailable"
            if isinstance(exc, StorageError)
            else str(exc)
        )
        return JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "code": code,
                    "message": message,
                    "correlation_id": correlation_id,
                    "retryable": retryable,
                    "details": {},
                }
            },
            headers={"X-Correlation-ID": correlation_id},
        )

    for error_type in (
        SecurityError,
        IngressError,
        StorageError,
        CommandError,
        CommunicationsError,
    ):
        app.add_exception_handler(error_type, domain_error)


def _mount(app: FastAPI, routers: Iterable[APIRouter]) -> None:
    for router in routers:
        app.include_router(router)


def mount_canonical_routers(app: FastAPI) -> None:
    """Mount the complete contract-backed route set exactly once."""
    install_domain_error_handler(app)
    _mount(app, CANONICAL_ROUTERS)


def mount_common_routers(app: FastAPI) -> None:
    _mount(app, COMMON_ROUTERS)


def mount_integration_routers(app: FastAPI) -> None:
    _mount(app, INTEGRATION_ROUTERS)


def mount_appolon_routers(app: FastAPI) -> None:
    _mount(app, APPOLON_ROUTERS)


def mount_monolith_routers(app: FastAPI) -> None:
    _mount(app, MONOLITH_ROUTERS)


def mount_legacy_monolith_routers(app: FastAPI) -> None:
    """Mount the deprecated, edge-denied aliases on a monolith application only."""
    _mount(app, LEGACY_MONOLITH_ONLY_ROUTERS)


def route_operations(app: FastAPI) -> list[tuple[str, str]]:
    """Every ``(method, path)`` the application serves, including mounted routers."""
    operations: list[tuple[str, str]] = []

    def walk(routes, prefix: str = "") -> None:
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                context = getattr(route, "include_context", None)
                walk(original.routes, prefix + (getattr(context, "prefix", "") or ""))
                continue
            path = getattr(route, "path", None)
            if path is None:
                continue
            methods = getattr(route, "methods", None)
            if not methods:
                # Starlette Mount / WebSocketRoute
                methods = ("WEBSOCKET",) if not hasattr(route, "app") or isinstance(route, APIRoute) else ("MOUNT",)
            for method in sorted(methods):
                operations.append((method, prefix + path))

    walk(app.routes)
    return operations


def assert_unique_routes(app: FastAPI) -> None:
    """Refuse an application that registers the same operation twice."""
    counts = Counter(route_operations(app))
    duplicates = sorted(op for op, count in counts.items() if count > 1)
    if duplicates:
        raise DuplicateRouteError(
            "duplicate route registrations: "
            + ", ".join(f"{method} {path}" for method, path in duplicates)
        )
