from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / "deploy" / "observability-alerts" / "production.env.example"
COMPOSE_PATH = (
    ROOT / "deploy" / "observability-alerts" / "compose.core-production.yaml"
)


def _environment() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def test_klyrow_secret_sources_and_container_targets_are_distinct_and_aligned() -> None:
    values = _environment()
    compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))

    expected = {
        "klyrow_alert_oidc_client_secret": (
            "KLYROW_ALERT_OIDC_CLIENT_SECRET_SOURCE_FILE",
            "KLYROW_ALERT_OIDC_CLIENT_SECRET_FILE",
            "klyrow-alert-oidc-client-secret",
        ),
        "klyrow_alert_ca": (
            "KLYROW_ALERT_MTLS_CA_SOURCE_FILE",
            "KLYROW_ALERT_MTLS_CA_FILE",
            "klyrow-alert-ca",
        ),
        "klyrow_alert_client_cert": (
            "KLYROW_ALERT_MTLS_CERT_SOURCE_FILE",
            "KLYROW_ALERT_MTLS_CERT_FILE",
            "klyrow-alert-client-cert",
        ),
        "klyrow_alert_client_key": (
            "KLYROW_ALERT_MTLS_KEY_SOURCE_FILE",
            "KLYROW_ALERT_MTLS_KEY_FILE",
            "klyrow-alert-client-key",
        ),
    }

    service_secrets = {
        item["source"]: item["target"]
        for item in compose["services"]["observability-alert-api"]["secrets"]
    }
    assert set(service_secrets) == set(expected)
    assert set(compose["secrets"]) == set(expected)

    for secret_name, (source_key, runtime_key, target) in expected.items():
        assert service_secrets[secret_name] == target
        assert values[runtime_key] == f"/run/secrets/{target}"
        assert values[source_key].startswith("/run/codestra/openbao/")
        assert values[source_key] != values[runtime_key]
        compose_source = compose["secrets"][secret_name]["file"]
        assert compose_source.startswith("${" + source_key + ":?")


def test_no_secret_value_is_embedded_in_source_manifests() -> None:
    values = _environment()
    secret_path_keys = [key for key in values if key.endswith("_SOURCE_FILE")]
    assert len(secret_path_keys) == 4
    assert all("<inject-secret>" not in values[key] for key in secret_path_keys)
    assert "BEGIN PRIVATE KEY" not in COMPOSE_PATH.read_text(encoding="utf-8")
