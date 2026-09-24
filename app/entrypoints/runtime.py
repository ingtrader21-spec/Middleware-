"""Process helpers for API and worker entrypoints.

Everything security- or readiness-relevant is delegated to the canonical
core: startup validation to :mod:`app.core.bootstrap`, the request guard to
:mod:`app.core.request_guard` and health/readiness to :mod:`app.core.health`.
This module only wires uvicorn, JSON logging and the worker loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TypedDict
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request
from prometheus_client import Counter, Gauge, make_asgi_app

from app.core.bootstrap import FEATURE_FLAG_STATE, StartupError, validate_startup
from app.core.config import Settings, settings
from app.core.health import (
    dependency_states,
    register_service_health_routes,
    version_payload,
)
from app.core.request_guard import RequestGuard, install_request_guard
from app.db.session import engine

__all__ = [
    "FEATURE_FLAG_STATE",
    "JsonFormatter",
    "add_api_runtime",
    "configure_logging",
    "engine",
    "integration_dependency_states",
    "run_api",
    "run_worker",
    "validate_runtime",
    "worker_app",
]

logger = logging.getLogger("codestra.runtime")
WORKER_CYCLES = Counter(
    "codestra_worker_cycles_total", "Worker cycles", ["service", "result"]
)
WORKER_READY = Gauge("codestra_worker_ready", "Worker readiness", ["service"])


class JsonFormatter(logging.Formatter):
    """Small JSON formatter that never serializes arbitrary request bodies."""

    def format(self, record: logging.LogRecord) -> str:
        value = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": os.getenv("SERVICE_NAME", "codestra-middleware"),
        }
        for name in ("correlation_id", "gateway_request_id", "queue", "result"):
            field = getattr(record, name, None)
            if field is not None:
                value[name] = str(field)
        if record.exc_info:
            value["exception"] = self.formatException(record.exc_info)
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


def validate_runtime(service: str, queue: str | None = None) -> None:
    """Fail closed before a process serves or consumes (canonical bootstrap)."""
    try:
        validate_startup(service, settings=settings, queue=queue)
    except StartupError as exc:
        raise RuntimeError(str(exc)) from exc


async def integration_dependency_states() -> dict[str, str]:
    """Probe the manifest's required dependencies without disclosing configuration."""
    return await dependency_states(settings)


def add_api_runtime(app: FastAPI, service: str, config: Settings | None = None) -> None:
    """Install the single guard and the service health surface on a narrow service app."""
    resolved = config or settings
    install_request_guard(app, RequestGuard(resolved))
    register_service_health_routes(app, service=service, settings=resolved)
    app.mount("/metrics", make_asgi_app())


def run_api(app: FastAPI, service: str) -> None:
    configure_logging()
    validate_runtime(service)
    # Container ingress is restricted by the private Docker network.
    uvicorn.run(
        app,
        host="0.0.0.0",  # nosec B104
        port=int(os.getenv("PORT", "8095")),
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )


Cycle = Callable[[], Awaitable[dict[str, object]]]


class WorkerState(TypedDict):
    ready: bool
    stopping: bool
    last_success: str | None
    last_error: str | None


def worker_app(service: str, queue: str, cycle: Cycle) -> FastAPI:
    state: WorkerState = {
        "ready": False,
        "stopping": False,
        "last_success": None,
        "last_error": None,
    }

    async def loop() -> None:
        interval = max(1, int(os.getenv("WORKER_INTERVAL_SECONDS", "30")))
        state["ready"] = True
        WORKER_READY.labels(service).set(1)
        while not state["stopping"]:
            try:
                result = await cycle()
                state["last_success"] = datetime.now(UTC).isoformat()
                state["last_error"] = None
                WORKER_CYCLES.labels(service, "success").inc()
                logger.info(
                    "worker_cycle_complete",
                    extra={"queue": queue, "result": result},
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state["last_error"] = type(exc).__name__
                WORKER_CYCLES.labels(service, "error").inc()
                logger.exception("worker_cycle_failed", extra={"queue": queue})
            await asyncio.sleep(interval)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(loop(), name=f"{service}-loop")
        try:
            yield
        finally:
            state["stopping"] = True
            state["ready"] = False
            WORKER_READY.labels(service).set(0)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await engine.dispose()

    app = FastAPI(title=service, lifespan=lifespan)

    @app.middleware("http")
    async def operational_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = str(uuid4())
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    @app.get("/healthz")
    @app.get("/health/live")
    async def health() -> dict[str, object]:
        return {"status": "ok", "service": service, "stopping": state["stopping"]}

    @app.get("/ready")
    @app.get("/readyz")
    @app.get("/health/ready")
    async def ready() -> dict[str, object]:
        return {
            "status": "ready" if state["ready"] else "not-ready",
            "service": service,
            "queue": queue,
            "last_success": state["last_success"],
            "last_error": state["last_error"],
        }

    @app.get("/dependencies")
    @app.get("/health/dependencies")
    async def dependencies() -> dict[str, object]:
        return {
            "database": "configured",
            "redis": "configured",
            "queue": queue,
            "live_writes_enabled": settings.live_writes_enabled,
        }

    @app.get("/version")
    async def version() -> dict[str, object]:
        return version_payload(settings, service)

    @app.get("/capabilities")
    async def capabilities() -> dict[str, object]:
        return {
            "service": service,
            "maintenance_mode": state["stopping"],
            "degraded_mode": state["last_error"] is not None,
            "business_writes_enabled": settings.live_writes_enabled,
            "external_delivery_enabled": settings.enable_external_delivery,
            "read_only_mode": not settings.live_writes_enabled,
            "supported_api_versions": ["v1"],
            "supported_operations": ["consume", "reconcile"],
            "queue": queue,
        }

    app.mount("/metrics", make_asgi_app())
    return app


def run_worker(service: str, queue: str, cycle: Cycle) -> None:
    configure_logging()
    validate_runtime(service, queue)
    app = worker_app(service, queue, cycle)
    # Container ingress is restricted by the private Docker network.
    uvicorn.run(
        app,
        host="0.0.0.0",  # nosec B104
        port=int(os.getenv("PORT", "8095")),
        access_log=False,
    )
