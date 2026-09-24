"""Per-component reconciliation vocabulary: never synced from a 200 without a digest read-back."""

from __future__ import annotations

from app.monitoring.routes import component_state

DESIRED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def test_synced_requires_a_matching_active_configuration_digest():
    assert (
        component_state(
            "prometheus", DESIRED, DESIRED, {"prometheus": DESIRED}, {}, {"prometheus"}
        )
        == "synced"
    )
    assert (
        component_state(
            "prometheus", DESIRED, DESIRED, {"prometheus": OTHER}, {}, {"prometheus"}
        )
        == "drifted"
    )
    assert (
        component_state(
            "prometheus", DESIRED, DESIRED, {"prometheus": None}, {}, {"prometheus"}
        )
        == "unknown"
    )
    assert (
        component_state("prometheus", DESIRED, DESIRED, {}, {}, {"prometheus"})
        == "unknown"
    )


def test_pending_applying_and_failed_come_from_release_and_collector_state():
    assert (
        component_state("grafana", OTHER, DESIRED, {"grafana": OTHER}, {}, {"grafana"})
        == "pending"
    )
    assert (
        component_state(
            "grafana",
            DESIRED,
            DESIRED,
            {"grafana": DESIRED},
            {"grafana": "applying"},
            {"grafana"},
        )
        == "applying"
    )
    assert (
        component_state(
            "grafana",
            DESIRED,
            DESIRED,
            {"grafana": DESIRED},
            {"grafana": "failed"},
            {"grafana"},
        )
        == "failed"
    )


def test_unrequired_or_undeclared_components_are_unknown():
    assert (
        component_state("loki", DESIRED, DESIRED, {"loki": DESIRED}, {}, {"prometheus"})
        == "unknown"
    )
    assert (
        component_state("loki", None, None, {"loki": DESIRED}, {}, {"loki"})
        == "unknown"
    )
