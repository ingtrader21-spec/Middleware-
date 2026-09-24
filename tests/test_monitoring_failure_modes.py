"""Failure-mode certification (source view): every telemetry outage degrades observability, never Middleware.

Covers the mission's failure matrix from the Middleware side:

- Prometheus / Loki / Tempo / Alertmanager / Grafana unreachable -> Middleware
  readiness is unaffected; reads of those backends answer 503 (never fabricated
  data); the reconciler reports ``unknown`` or ``failed``, never ``synced``.
- Collector cannot reach a component -> that component is ``failed`` and the
  service state folds to ``failed``.
- Observations stop arriving -> freshness lapses to ``unknown`` and the service
  can never be ``synced`` from an old success.
- Middleware unavailable to the collector -> the collector fails closed and
  writes nothing (covered in ``test_monitoring_collector``).
- OpenBao sealed -> health projection reports it and Middleware never unseals.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta

import pytest

from app.monitoring.routes import service_state
from tests.test_integrated_monitoring import DIGEST, observation, system

# The fixtures are imported for pytest discovery and are then shadowed by the
# test parameters that receive them; referencing them here keeps that explicit.
SHARED_FIXTURES = (observation, system)

OTHER = "sha256:" + "b" * 64


def collector_headers(system_fixture):
    return system_fixture.auth(role="monitoring_collector", client="collector")


def reconcile(s):
    return s.client.post(
        "/platform/v1/sync/reconciliations",
        json={"environment": "production", "service_ids": ["sample-api"]},
        headers=s.auth(),
    ).json()["data"]["results"][0]


def test_readiness_never_consults_telemetry_backends():
    # The readiness decision is the health authority (app.core.health); it must
    # report only the runtime's own dependencies and never reach a telemetry
    # backend, so an outage of the monitoring stack cannot mark the API unready.
    from app.core import health

    source = inspect.getsource(health)
    for backend in (
        "prometheus",
        "loki",
        "tempo",
        "alertmanager",
        "grafana",
        "monitoring",
    ):
        assert backend not in source.lower()
    assert set(health.ReadinessSnapshot.__dataclass_fields__) == {
        "ready",
        "components",
        "dependencies",
        "reason",
        "checked_at",
    }


def test_no_observation_means_unknown_not_synced(system):
    s = system
    result = reconcile(s)
    assert result["state"] == "unknown"
    assert result["component_states"] == {"prometheus": "unknown"}
    assert result["missing_components"] == ["prometheus"]


def test_collector_reported_failure_folds_to_failed(system):
    s = system
    body = observation(
        "config",
        data={"component": "prometheus", "config_digest": "", "status": "failed"},
    )
    response = s.client.post(
        "/platform/v1/runtime/observations", json=body, headers=collector_headers(s)
    )
    assert response.status_code == 200, response.text
    result = reconcile(s)
    assert result["component_states"] == {"prometheus": "failed"}
    assert result["state"] == "failed"


def test_stale_success_can_never_keep_a_service_synced(system, monkeypatch):
    s = system
    fresh = observation(
        "config", data={"component": "prometheus", "config_digest": DIGEST}
    )
    assert (
        s.client.post(
            "/platform/v1/runtime/observations",
            json=fresh,
            headers=collector_headers(s),
        ).status_code
        == 200
    )
    assert reconcile(s)["state"] == "synced"

    class Later(datetime):
        """Ten minutes pass without a new observation."""

        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(minutes=10)

    monkeypatch.setattr("app.monitoring.routes.datetime", Later)
    result = reconcile(s)
    assert result["state"] == "unknown" and result["component_states"] == {
        "prometheus": "unknown"
    }
    assert result["components"] == {}


def test_drift_wins_over_a_later_matching_component_when_any_required_component_drifts():
    states = {"prometheus": "synced", "alertmanager": "drifted"}
    assert (
        service_state(DIGEST, DIGEST, {"prometheus", "alertmanager"}, states)
        == "drifted"
    )
    states = {"prometheus": "synced", "alertmanager": "failed", "grafana": "drifted"}
    assert (
        service_state(DIGEST, DIGEST, {"prometheus", "alertmanager", "grafana"}, states)
        == "failed"
    )
    assert (
        service_state(DIGEST, DIGEST, {"prometheus"}, {"prometheus": "applying"})
        == "applying"
    )
    assert (
        service_state(DIGEST, DIGEST, {"prometheus"}, {"prometheus": "synced"})
        == "synced"
    )
    assert (
        service_state(DIGEST, OTHER, {"prometheus"}, {"prometheus": "synced"})
        == "pending-release-approval"
    )
    assert service_state(DIGEST, DIGEST, set(), {}) == "unknown"
    assert (
        service_state(None, None, {"prometheus"}, {"prometheus": "synced"}) == "unknown"
    )


@pytest.mark.parametrize(
    ("backend", "path", "body"),
    [
        (
            "prometheus",
            "/v1/observability/metrics/query",
            {
                "service_id": "sample-api",
                "environment": "production",
                "query_id": "metrics",
            },
        ),
        (
            "loki",
            "/v1/observability/logs/query",
            {
                "service_id": "sample-api",
                "environment": "production",
                "query_id": "logs",
            },
        ),
        (
            "tempo",
            "/v1/observability/traces/search",
            {
                "service_id": "sample-api",
                "environment": "production",
                "query_id": "traces-search",
            },
        ),
    ],
)
def test_backend_outage_answers_503_and_never_fabricates_data(
    system, backend, path, body
):
    s = system
    s.config["backends"].pop(backend)
    response = s.client.post(path, json=body, headers=s.auth())
    assert response.status_code == 503, response.text
    assert "result" not in response.text.lower() or response.json().get("data") in (
        None,
        [],
    )


def test_sealed_openbao_is_reported_and_never_unsealed(system):
    s = system
    response = s.client.get(
        "/v1/observability/secrets/health?service_id=sample-api&environment=production",
        headers=s.auth(),
    )
    assert response.status_code == 200, response.text
    text = response.text
    assert "must-not-return" not in text
    assert '"sealed":true' in text.replace(" ", "") or '"sealed": true' in text
    unseal_calls = [
        c
        for c in s.calls
        if "unseal" in str(c.url) or c.method != "GET" and "openbao" in str(c.url.host)
    ]
    assert unseal_calls == []
