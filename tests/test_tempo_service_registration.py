"""Validate the Tempo service registration and monitoring registry linkage."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRATION_PATH = ROOT / "contracts" / "observability" / "tempo-service-registration.v1.json"
REGISTRY_PATH = ROOT / "monitoring-integration.v1.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_tempo_registration_contract() -> None:
    registration = _load(REGISTRATION_PATH)

    assert registration["service_id"] == "tempo"
    assert registration["repository"] == "appolon1908-hue/Codestra-Tempo"
    assert registration["environments"] == ["staging", "production"]
    assert registration["required_signals"] == ["traces"]
    assert registration["required_components"] == ["tempo", "alloy", "prometheus"]
    assert registration["native_api"] == {
        "health": "/ready",
        "readiness": "/ready",
        "metrics": "/metrics",
        "trace_by_id": "/api/traces/{trace_id}",
        "otlp_grpc": "4317",
        "otlp_http": "4318",
    }
    assert registration["backend_binding"]["transport"] == "private_mtls"
    assert registration["backend_binding"]["tenant_header"] == "X-Scope-OrgID"
    assert set(registration["observation_sources"]) == {"alloy", "prometheus"}
    assert registration["production_activation"] is False
    assert registration["runtime_coverage"] == "unverified"


def test_tempo_registration_is_in_monitoring_registry() -> None:
    registration = _load(REGISTRATION_PATH)
    registry = _load(REGISTRY_PATH)

    assert registry["service_ids"] == [registration["service_id"]]
