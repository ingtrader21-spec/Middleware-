from __future__ import annotations

import json
import logging
from io import StringIO

from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import JsonFormatter


def test_metrics_require_monitoring_identity_and_use_bounded_labels(
    test_settings,
    runtime,
) -> None:
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        correlation_id = "corr-private-search-value"
        health = client.get("/health", headers={"X-Correlation-ID": correlation_id})
        denied = client.get("/metrics")
        metrics = client.get(
            "/metrics",
            headers={
                "Authorization": (
                    "Bearer valid-monitoring-readonly-metrics.read"
                )
            },
        )

    assert health.headers["X-Correlation-ID"] == correlation_id
    assert denied.status_code == 401
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert 'operation="/health"' in metrics.text
    assert 'release_sha="unknown"' in metrics.text
    assert 'dependency="identity_jwks"' in metrics.text
    assert correlation_id not in metrics.text


def test_valid_traceparent_is_propagated_and_invalid_value_is_dropped(
    test_settings,
    runtime,
) -> None:
    valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        propagated = client.get("/health", headers={"traceparent": valid})
        dropped = client.get("/health", headers={"traceparent": "secret-value"})

    assert propagated.headers["traceparent"] == valid
    assert "traceparent" not in dropped.headers


def test_request_logs_are_json_and_exclude_headers_and_payloads(
    test_settings,
    runtime,
) -> None:
    correlation_id = "corr-log-safe"
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("codestra.middleware.request")
    logger.addHandler(handler)
    app = create_app(settings=test_settings, runtime=runtime)
    try:
        with TestClient(app) as client:
            client.get(
                "/health",
                headers={
                    "X-Correlation-ID": correlation_id,
                    "Authorization": "Bearer must-never-be-logged",
                },
            )
    finally:
        logger.removeHandler(handler)

    records = [
        json.loads(line)
        for line in stream.getvalue().splitlines()
        if line.startswith("{")
    ]
    record = next(
        item for item in records if item.get("correlation_id") == correlation_id
    )
    assert record["event"] == "http.request.completed"
    assert record["operation"] == "/health"
    assert record["status_code"] == 200
    assert "must-never-be-logged" not in json.dumps(record)
