"""The single FastAPI application factory of the Middleware.

``create_app()`` builds every Middleware HTTP process from one code path:

* the canonical settings (``app.core.config``): the one process-wide
  instance after the canonical configuration validation, or an injected,
  pre-validated ``Settings`` in tests,
* one :class:`~app.core.runtime.RuntimeContainer`, built in the lifespan
  (or injected by tests) and exposed as ``app.state.runtime``,
* the route groups of :mod:`app.router_registry`, selected by
  :class:`AppProfile` — the deployed integration API, the control-plane
  canary, or the in-process monolith that serves everything,
* the single request guard (:mod:`app.core.request_guard`), the canonical
  error envelope and OpenAPI shaping, and the single health/readiness
  authority (:mod:`app.core.health`).

Startup is fail-closed: a configuration defect raises before the process
serves; a missing runtime dependency leaves the process live but unready
(503 on readiness, 503 from every control-plane route) until the container
can be built.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum

from fastapi import Depends, FastAPI

from app import appolon_routes
from app.api_inputs import restrict_sms_identity
from app.core.bootstrap import (
    SERVICE_CANONICAL_API,
    SERVICE_INTEGRATION_API,
    validate_configuration,
)
from app.core.config import Settings
from app.core.config import settings as process_settings
from app.core.health import RuntimeState, register_health_routes
from app.core.request_guard import RequestGuard, install_request_guard
from app.core.runtime import RuntimeContainer
from app.legacy_effects import enforce_legacy_effect_registry, install_legacy_effect_handler
from app.observability import MiddlewareObservability
from app.platform.api import router as platform_kernel_router
from app.router_registry import (
    APPOLON_ROUTERS,
    LEGACY_MONOLITH_ONLY_ROUTERS,
    assert_unique_routes,
    mount_appolon_routers,
    mount_canonical_routers,
    mount_common_routers,
    mount_integration_routers,
    mount_legacy_monolith_routers,
    mount_monolith_routers,
)

logger = logging.getLogger("codestra.application")

APPLICATION_TITLE = "Codestra Middleware API"


class AppProfile(str, Enum):
    """Which route groups a process serves. Every profile shares the core."""

    # ``python -m app.entrypoints.integration_api`` (deploy/compose.runtime.yaml):
    # the contract-backed canonical routes plus the integration surface.
    INTEGRATION = "integration"
    # ``uvicorn app.main:create_app --factory`` (production read-only canary):
    # the canonical routes plus the Appolon control plane.
    CONTROL_PLANE = "control-plane"
    # ``app.main:app``: every group, including the edge-denied legacy aliases.
    MONOLITH = "monolith"


_DEFAULT_SERVICE = {
    AppProfile.INTEGRATION: SERVICE_INTEGRATION_API,
    AppProfile.CONTROL_PLANE: SERVICE_CANONICAL_API,
    AppProfile.MONOLITH: SERVICE_CANONICAL_API,
}


def create_app(
    settings: Settings | None = None,
    runtime: RuntimeContainer | None = None,
    *,
    profile: AppProfile = AppProfile.CONTROL_PLANE,
    legacy_monolith: bool = False,
    service: str | None = None,
) -> FastAPI:
    """Build the canonical application for ``profile``.

    ``legacy_monolith=True`` is shorthand for :attr:`AppProfile.MONOLITH`.
    ``settings``/``runtime`` are injected by tests; a production process
    passes neither. Per-service process requirements are applied by
    ``app.entrypoints.runtime.run_api`` before serving.
    """
    if legacy_monolith:
        profile = AppProfile.MONOLITH
    profile = AppProfile(profile)
    service_name = service or _DEFAULT_SERVICE[profile]
    resolved = settings if settings is not None else validate_configuration(process_settings)[0]

    state = RuntimeState(settings=resolved, runtime=runtime, owns_runtime=False)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if state.runtime is None:
            await state.build()
        app.state.runtime = state.runtime
        try:
            yield
        finally:
            await state.close()
            app.state.runtime = None

    app = FastAPI(
        title=APPLICATION_TITLE,
        version=resolved.app_version,
        dependencies=[Depends(restrict_sms_identity)],
        docs_url=None if resolved.app_env in {"staging", "production"} else "/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.runtime_state = state
    app.state.runtime = runtime
    app.state.profile = profile
    app.state.service = service_name
    telemetry = MiddlewareObservability(resolved)
    app.state.observability = telemetry

    def runtime_available() -> bool:
        # Readiness rebuilds may replace the container after startup.
        app.state.runtime = state.runtime
        return state.runtime is not None

    # Control-plane routers verify a service JWT in every handler; the
    # deprecated n8n aliases are the same handlers under their legacy paths.
    # The kernel router verifies the Keycloak JWT as the first statement of
    # every handler, on every profile.
    handler_authenticated: tuple = (platform_kernel_router,)
    if profile in {AppProfile.CONTROL_PLANE, AppProfile.MONOLITH}:
        handler_authenticated = (platform_kernel_router,) + APPOLON_ROUTERS
    if profile is AppProfile.MONOLITH:
        handler_authenticated = (platform_kernel_router,) + APPOLON_ROUTERS + LEGACY_MONOLITH_ONLY_ROUTERS
    install_request_guard(
        app,
        RequestGuard(
            resolved,
            handler_authenticated_routers=handler_authenticated,
            telemetry=telemetry,
            runtime_available=runtime_available,
        ),
    )
    register_health_routes(app, service=service_name, state=state)
    mount_canonical_routers(app)
    mount_common_routers(app)
    if profile in {AppProfile.INTEGRATION, AppProfile.MONOLITH}:
        mount_integration_routers(app)
    if profile in {AppProfile.CONTROL_PLANE, AppProfile.MONOLITH}:
        mount_appolon_routers(app)
    if profile is AppProfile.MONOLITH:
        mount_monolith_routers(app)
        mount_legacy_monolith_routers(app)
    # The Appolon handlers are a superset of the registry's domain handler
    # (same envelope plus the auth-denial metric); installed last so they win.
    appolon_routes.install_error_handlers(app)
    install_legacy_effect_handler(app)
    assert_unique_routes(app)
    # Fail closed: a DENIED legacy effect path mounted without its denial
    # refuses to build (config/legacy-effect-registry.v1.json).
    enforce_legacy_effect_registry(app)
    appolon_routes.install_canonical_openapi(app)
    return app
