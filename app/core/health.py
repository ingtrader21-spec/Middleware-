"""The single liveness/readiness/version authority of a Middleware process.

Liveness (``/health``, ``/healthz``, ``/health/live``) answers 200 whenever
the process can serve HTTP; it never touches a dependency.

Readiness (``/ready``, ``/readyz``, ``/health/ready``, ``/readiness``) is
fail-closed:

* no :class:`~app.core.runtime.RuntimeContainer` (startup failed, or the
  application was created without one) -> 503,
* any configured component of the container ``not_ready`` -> 503,
* otherwise 200.

A process whose runtime failed to start stays live and unready; every
``runtime_rebuild_interval_seconds`` a readiness probe triggers one guarded
rebuild attempt so the service recovers once its dependencies return. Nothing
is ever reported ready without a successful probe.

``/version``, ``/capabilities`` and ``/dependencies`` read only the canonical
settings and the readiness snapshot; they never expose secrets or addresses.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import Settings
from app.core.runtime import (
    RuntimeContainer,
    build_runtime_container,
    identity_probe_required,
)

logger = logging.getLogger("codestra.health")

LIVENESS_PATHS = ("/health", "/healthz", "/health/live")
READINESS_PATHS = ("/ready", "/readyz", "/health/ready", "/readiness")
DEPENDENCY_PATHS = ("/dependencies", "/health/dependencies")

_POSTGRES_COMPONENTS = (
    "inbox_store",
    "command_store",
    "communications_store",
    "incident_store",
    "automation_store",
    "realtime_store",
    "sql_engine",
    "alembic_head",
)
_STATE_BY_STATUS = {
    "ready": "online",
    "not_ready": "unavailable",
    "not_configured": "not_configured",
}


@dataclass
class RuntimeState:
    """What the application knows about its runtime container."""

    settings: Settings
    runtime: RuntimeContainer | None = None
    owns_runtime: bool = False
    startup_failed: bool = False
    startup_error: str | None = None
    last_build_attempt: float = field(default_factory=lambda: float("-inf"))
    _rebuild_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def build(self) -> None:
        """Try to build the container once; failures leave the process unready."""
        self.last_build_attempt = time.monotonic()
        try:
            self.runtime = await build_runtime_container(self.settings)
        except Exception as exc:
            self.runtime = None
            self.startup_failed = True
            self.startup_error = type(exc).__name__
            logger.warning(
                "runtime unavailable; readiness remains closed",
                extra={"result": self.startup_error},
            )
        else:
            self.owns_runtime = True
            self.startup_failed = False
            self.startup_error = None

    async def rebuild_if_due(self) -> None:
        """Retry a failed startup at most once per rebuild interval."""
        if self.runtime is not None or not self.startup_failed:
            return
        if time.monotonic() - self.last_build_attempt < self.settings.runtime_rebuild_interval_seconds:
            return
        if self._rebuild_lock.locked():
            return
        async with self._rebuild_lock:
            if self.runtime is None:
                await self.build()

    async def close(self) -> None:
        if self.runtime is not None and self.owns_runtime:
            await self.runtime.close()
        self.runtime = None


@dataclass(frozen=True)
class ReadinessSnapshot:
    ready: bool
    components: dict[str, str]
    dependencies: dict[str, str]
    reason: str | None
    checked_at: str

    def payload(self, service: str, settings: Settings) -> dict[str, Any]:
        return {
            "status": "ready" if self.ready else "not-ready",
            "service": service,
            "components": self.components,
            "dependencies": self.dependencies,
            "authorization": self.dependencies["keycloak"],
            "database": self.dependencies["postgres"],
            "redis": self.dependencies["redis"],
            "delivery": "enabled" if settings.enable_external_delivery else "disabled",
            "reason": self.reason,
            "checked_at": self.checked_at,
        }


def _aggregate(components: dict[str, str], names: tuple[str, ...]) -> str:
    statuses = [components[name] for name in names if name in components]
    if any(status == "not_ready" for status in statuses):
        return "unavailable"
    if any(status == "ready" for status in statuses):
        return "online"
    return "not_configured"


def dependencies_from_components(components: dict[str, str]) -> dict[str, str]:
    return {
        "postgres": _aggregate(components, _POSTGRES_COMPONENTS),
        "redis": _STATE_BY_STATUS.get(components.get("replay_guard", "not_configured"), "unavailable"),
        "keycloak": _STATE_BY_STATUS.get(components.get("identity_jwks", "not_configured"), "unavailable"),
    }


async def dependency_states(settings: Settings, *, engine: Any = None) -> dict[str, str]:
    """Probe Postgres, Redis and Keycloak without a runtime container.

    Used when startup failed so operators still learn which dependency is
    down. Never discloses configuration.
    """
    timeout = settings.readiness_timeout_seconds

    async def database() -> str:
        try:
            target = engine
            if target is None:
                from app.db.session import get_engine

                target = get_engine()
            async with asyncio.timeout(timeout):
                async with target.connect() as connection:
                    await connection.execute(text("SELECT 1"))
            return "online"
        except Exception:
            return "unavailable"

    async def redis() -> str:
        if not settings.redis_url:
            return "not_configured"
        try:
            async with asyncio.timeout(timeout):
                async with Redis.from_url(
                    settings.redis_url, socket_timeout=2, socket_connect_timeout=2
                ) as client:
                    return "online" if await client.ping() else "unavailable"
        except Exception:
            return "unavailable"

    async def keycloak() -> str:
        identity = settings.identity
        if not identity_probe_required(settings) or not identity.jwks_url:
            return "not_configured"
        try:
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(
                    timeout=identity.jwks_timeout_seconds, follow_redirects=False, trust_env=False
                ) as client:
                    response = await client.get(identity.jwks_url)
                    response.raise_for_status()
                    keys = jwt.PyJWKSet.from_dict(response.json()).keys
            usable = any(
                key.key_type == "RSA"
                and key.algorithm_name == "RS256"
                and key.public_key_use in (None, "sig")
                for key in keys
            )
            return "online" if usable else "unavailable"
        except Exception:
            return "unavailable"

    states = await asyncio.gather(database(), redis(), keycloak())
    return dict(zip(("postgres", "redis", "keycloak"), states, strict=True))


async def readiness_snapshot(state: RuntimeState) -> ReadinessSnapshot:
    """The one readiness decision; every readiness route renders this."""
    await state.rebuild_if_due()
    checked_at = datetime.now(UTC).isoformat()
    runtime = state.runtime
    if runtime is None:
        return ReadinessSnapshot(
            ready=False,
            components={},
            dependencies=await dependency_states(state.settings),
            reason=state.startup_error or "runtime_unavailable",
            checked_at=checked_at,
        )
    report = await runtime.readiness()
    failed = sorted(name for name, status in report.components.items() if status == "not_ready")
    return ReadinessSnapshot(
        ready=report.ready,
        components=dict(report.components),
        dependencies=dependencies_from_components(report.components),
        reason=None if report.ready else "components_not_ready:" + ",".join(failed),
        checked_at=checked_at,
    )


def version_payload(settings: Settings, service: str) -> dict[str, Any]:
    return {
        "service": service,
        "version": settings.app_version,
        "environment": settings.app_env,
        "runtime_profile_id": settings.runtime_profile_id or "local-unlocked",
        "source_sha": settings.source_sha,
        "git_sha": settings.source_sha,
        "release_id": settings.release_id,
        "image_digest": settings.image_digest,
        "build_timestamp": settings.build_time,
        "schema_head": settings.schema_head,
        "schema_version": settings.schema_head,
        "configuration_checksum": settings.configuration_checksum,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def capabilities_payload(settings: Settings, service: str) -> dict[str, Any]:
    """Authoritative, non-secret runtime safety state."""
    external_delivery = settings.enable_external_delivery
    business_writes = settings.live_writes_enabled
    umbrella = settings.umbrella_controls
    return {
        "service": service,
        "environment": settings.app_env,
        "tenant_aware": True,
        "maintenance_mode": False,
        "degraded_mode": False,
        "business_writes_enabled": business_writes,
        "live_writes_enabled": business_writes,
        "external_delivery_enabled": external_delivery,
        "live_email_enabled": settings.allow_live_email,
        "live_sms_enabled": settings.allow_live_sms,
        "live_pstn_enabled": settings.external_dial_enabled,
        "live_social_publish_enabled": settings.social_publish_enabled,
        "live_advertising_enabled": umbrella["LIVE_ADVERTISING_ENABLED"],
        "simulation_enabled": not (business_writes or external_delivery),
        "read_only_mode": not business_writes,
        "supported_api_versions": ["platform/v1", "api/v1", "api/v2", "v1", "v2"],
        "supported_operations": ["command", "status", "reconcile"],
        "provider_availability": "enabled" if external_delivery else "disabled",
        "reconciliation_available": True,
        "backup_authority_status": "unknown",
        "required_compliance_gates": ["business-write-activation", "provider-activation"],
        "capabilities": {
            **{name: bool(value) for name, value in umbrella.items()},
            "PRODUCTION_DIALING": settings.production_dialing != "DISABLED",
        },
    }


def dependencies_payload(
    settings: Settings, service: str, snapshot: ReadinessSnapshot
) -> dict[str, Any]:
    return {
        "service": service,
        "database": snapshot.dependencies["postgres"],
        "redis": snapshot.dependencies["redis"],
        "keycloak": snapshot.dependencies["keycloak"],
        "dependencies": snapshot.components,
        "live_writes_enabled": settings.live_writes_enabled,
        "odoo_delivery_enabled": settings.odoo_delivery_enabled,
        "n8n_delivery_enabled": settings.n8n_delivery_enabled,
        "send_events": settings.send_events,
        "broad_event_send_enabled": settings.broad_event_send_enabled,
        "broad_event_delivery_enabled": settings.broad_event_delivery_enabled,
        "production_n8n_enabled": settings.production_n8n_enabled,
        "n8n_production_workflows_enabled": settings.n8n_production_workflows_enabled,
        "enable_external_delivery": settings.enable_external_delivery,
        "broad_event_pipeline_enabled": settings.broad_event_pipeline_enabled,
        "checked_at": snapshot.checked_at,
    }


async def service_readiness_snapshot(settings: Settings, *, database_required: bool) -> ReadinessSnapshot:
    """Readiness for a narrow service process that hosts no runtime container.

    Only the SQL engine is probed, and only when the service declares the
    database required; Redis and Keycloak are reported as ``not_probed``.
    """
    checked_at = datetime.now(UTC).isoformat()
    if not database_required:
        return ReadinessSnapshot(
            ready=True,
            components={"sql_engine": "not_configured"},
            dependencies={"postgres": "not-required", "redis": "not_probed", "keycloak": "not_probed"},
            reason=None,
            checked_at=checked_at,
        )
    states = await dependency_states(settings)
    database = states["postgres"]
    return ReadinessSnapshot(
        ready=database == "online",
        components={"sql_engine": "ready" if database == "online" else "not_ready"},
        dependencies={"postgres": database, "redis": "not_probed", "keycloak": "not_probed"},
        reason=None if database == "online" else "database_unavailable",
        checked_at=checked_at,
    )


def _mount_health(
    app: FastAPI,
    *,
    service: str,
    settings: Settings,
    snapshot: Callable[[], Awaitable[ReadinessSnapshot]],
) -> None:
    async def liveness() -> dict[str, str]:
        return {"status": "ok", "service": service, "component": "api"}

    async def readiness(request: Request) -> JSONResponse:
        current = await snapshot()
        return JSONResponse(
            current.payload(service, settings),
            status_code=200 if current.ready else 503,
        )

    async def version() -> dict[str, Any]:
        return version_payload(settings, service)

    async def capabilities() -> dict[str, Any]:
        return capabilities_payload(settings, service)

    async def dependencies() -> dict[str, Any]:
        return dependencies_payload(settings, service, await snapshot())

    # Registered one literal path at a time so the source contract validator
    # (scripts/validate_staging_intake_observability_contract.py) can prove
    # that nothing here shadows a governed route.
    app.add_api_route("/health", liveness, methods=["GET"], tags=["health"], name="liveness")
    app.add_api_route("/healthz", liveness, methods=["GET"], tags=["health"], name="liveness")
    app.add_api_route("/health/live", liveness, methods=["GET"], tags=["health"], name="liveness")
    app.add_api_route("/ready", readiness, methods=["GET"], tags=["health"], name="readiness", response_model=None)
    app.add_api_route("/readyz", readiness, methods=["GET"], tags=["health"], name="readiness", response_model=None)
    app.add_api_route("/health/ready", readiness, methods=["GET"], tags=["health"], name="readiness", response_model=None)
    app.add_api_route("/readiness", readiness, methods=["GET"], tags=["health"], name="readiness", response_model=None)
    app.add_api_route("/version", version, methods=["GET"], tags=["health"], name="version")
    app.add_api_route("/capabilities", capabilities, methods=["GET"], tags=["health"], name="capabilities")
    app.add_api_route("/dependencies", dependencies, methods=["GET"], tags=["health"], name="dependencies")
    app.add_api_route("/health/dependencies", dependencies, methods=["GET"], tags=["health"], name="dependencies")


def register_health_routes(app: FastAPI, *, service: str, state: RuntimeState) -> None:
    """Mount the canonical, container-backed health surface exactly once."""

    async def snapshot() -> ReadinessSnapshot:
        return await readiness_snapshot(state)

    _mount_health(app, service=service, settings=state.settings, snapshot=snapshot)


def register_service_health_routes(app: FastAPI, *, service: str, settings: Settings) -> None:
    """Mount the health surface for a narrow service without a runtime container.

    ``settings.health_require_database`` is read per probe so the declared
    requirement, not a snapshot taken at import, decides readiness.
    """

    async def snapshot() -> ReadinessSnapshot:
        return await service_readiness_snapshot(
            settings, database_required=settings.health_require_database
        )

    _mount_health(app, service=service, settings=settings, snapshot=snapshot)
