from __future__ import annotations

import json
import logging
import re
import sys
import time
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

from app.core.config import Settings
from .intake_observability import IntakeMetrics, collect_intake_backlog


SERVICE = "middleware-api"
COMPONENT = "api"
CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
TRACEPARENT = re.compile(
    r"^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}$"
)


def safe_correlation_id(value: str | None) -> str | None:
    if value is None or CORRELATION_ID.fullmatch(value) is None:
        return None
    return value


def safe_traceparent(value: str | None) -> str | None:
    if value is None or TRACEPARENT.fullmatch(value) is None:
        return None
    return value


def trace_id(traceparent: str | None) -> str | None:
    if traceparent is None:
        return None
    return traceparent.split("-", 3)[1]


class JsonFormatter(logging.Formatter):
    """Render a bounded application log record without request or secret material."""

    _fields = (
        "service",
        "component",
        "event",
        "operation",
        "correlation_id",
        "trace_id",
        "result",
        "release_sha",
        "image_digest",
        "method",
        "status_code",
        "duration_ms",
    )

    def format(self, record: logging.LogRecord) -> str:
        value: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        for field in self._fields:
            item = getattr(record, field, None)
            if item is not None:
                value[field] = item
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def request_logger() -> logging.Logger:
    logger = logging.getLogger("codestra.middleware.request")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(getattr(handler, "_codestra_json", False) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        handler._codestra_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    return logger


class MiddlewareObservability:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.registry = CollectorRegistry(auto_describe=True)
        labels = ("service", "component", "environment")
        self._base = (SERVICE, COMPONENT, settings.app_env)
        self.requests = Counter(
            "codestra_http_requests_total",
            "Completed HTTP requests.",
            (*labels, "operation", "method", "status"),
            registry=self.registry,
        )
        self.duration = Histogram(
            "codestra_http_request_duration_seconds",
            "HTTP request duration in seconds.",
            (*labels, "operation", "method"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=self.registry,
        )
        self.active = Gauge(
            "codestra_http_active_requests",
            "HTTP requests currently being handled.",
            labels,
            registry=self.registry,
        )
        self.auth_denials = Counter(
            "codestra_auth_denials_total",
            "Authentication and authorization denials.",
            (*labels, "operation", "result"),
            registry=self.registry,
        )
        self.operations_dashboard_auth_failures = Counter(
            "codestra_operations_dashboard_auth_failures_total",
            "Authentication and authorization denials for read-only operations dashboard endpoints.",
            (*labels, "reason"),
            registry=self.registry,
        )
        self.operations_dashboard_release_gate_state = Gauge(
            "codestra_operations_dashboard_release_gate_state",
            "Read-only operations dashboard release-gate state (1 when current).",
            (*labels, "gate", "state"),
            registry=self.registry,
        )
        self.operations_dashboard_canary_state = Gauge(
            "codestra_operations_dashboard_canary_state",
            "Read-only operations dashboard provider canary state (1 when current).",
            (*labels, "provider", "channel", "state"),
            registry=self.registry,
        )
        self.readiness = Gauge(
            "codestra_readiness",
            "Readiness of mandatory runtime components (1 ready, 0 not ready).",
            (*labels, "dependency"),
            registry=self.registry,
        )
        self.release = Gauge(
            "codestra_release_info",
            "Immutable release identity for this process.",
            (
                *labels,
                "release_sha",
                "image_digest",
                "schema_or_migration_head",
                "version",
            ),
            registry=self.registry,
        )
        self.started = Gauge(
            "codestra_start_time_seconds",
            "Unix timestamp when this application process started.",
            (*labels, "release_sha"),
            registry=self.registry,
        )
        self.intake = IntakeMetrics(self.registry, settings.app_env)
        self.release.labels(
            *self._base,
            settings.source_sha,
            settings.image_digest,
            settings.schema_head,
            settings.app_version,
        ).set(1)
        self.started.labels(*self._base, settings.source_sha).set(time.time())
        self.logger = request_logger()

    def start_request(self) -> float:
        self.active.labels(*self._base).inc()
        return time.perf_counter()

    def finish_request(
        self,
        *,
        started: float,
        operation: str,
        method: str,
        status_code: int,
        correlation_id: str,
        traceparent: str | None,
        intake_context: dict[str, str] | None = None,
    ) -> None:
        elapsed = max(time.perf_counter() - started, 0.0)
        normalized_method = method.upper() if method.upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
        } else "OTHER"
        self.active.labels(*self._base).dec()
        self.requests.labels(
            *self._base,
            operation,
            normalized_method,
            str(status_code),
        ).inc()
        self.duration.labels(*self._base, operation, normalized_method).observe(elapsed)
        self.intake.record_http_outcome(
            operation,
            status_code,
            elapsed,
            intake_context,
        )
        self.logger.info(
            "http_request_completed",
            extra={
                "service": SERVICE,
                "component": COMPONENT,
                "event": "http.request.completed",
                "operation": operation,
                "correlation_id": correlation_id,
                "trace_id": trace_id(traceparent),
                "result": "success" if status_code < 400 else "failure",
                "release_sha": self.settings.source_sha,
                "image_digest": self.settings.image_digest,
                "method": normalized_method,
                "status_code": status_code,
                "duration_ms": round(elapsed * 1000, 3),
            },
        )

    def record_auth_denial(self, operation: str, result: str) -> None:
        self.auth_denials.labels(*self._base, operation, result).inc()
        if operation.startswith("/v1/operations-dashboard/"):
            self.operations_dashboard_auth_failures.labels(*self._base, result).inc()

    def record_operations_dashboard_release_gates(self, gates: dict[str, bool]) -> None:
        for gate, passed in gates.items():
            self.operations_dashboard_release_gate_state.labels(
                *self._base,
                gate,
                "passed" if passed else "blocked",
            ).set(1)

    def record_operations_dashboard_canaries(
        self,
        canaries: list[dict[str, str]],
    ) -> None:
        for canary in canaries:
            self.operations_dashboard_canary_state.labels(
                *self._base,
                canary.get("id", "unknown"),
                canary.get("channel", "unknown"),
                canary.get("status", "unknown"),
            ).set(1)

    def record_readiness(self, components: dict[str, str]) -> None:
        for dependency, status in components.items():
            if status == "not_configured":
                continue
            self.readiness.labels(*self._base, dependency).set(
                1 if status == "ready" else 0
            )

    async def refresh_intake_backlog(self, inbox: object) -> None:
        try:
            snapshot = await collect_intake_backlog(inbox)
        except Exception:
            self.intake.record_backlog_failure()
            raise
        self.intake.set_backlog(snapshot)

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
