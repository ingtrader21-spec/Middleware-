#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "config" / "runtime-profiles.v1.json"
EFFECT_FLAGS = {
    "OUTBOX_DISPATCH_ENABLED",
    "SEND_EVENTS",
    "ENABLE_EXTERNAL_DELIVERY",
    "LIVE_WRITE",
    "LIVE_WRITES",
    "ODOO_WRITE",
    "CALLBACK_DISPATCH",
    "N8N_DELIVERY_ENABLED",
    "VICIDIAL_WRITES_ENABLED",
    "EXTERNAL_DIAL_ENABLED",
    "PRODUCTION_CALLBACKS_ENABLED",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "SMS_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED",
    "CRAWLER_EXECUTION_ENABLED",
    "SCRAPPER_EXECUTION_ENABLED",
}


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=" or not key or key in result:
            raise AssertionError(f"invalid environment template line in {path.name}")
        result[key] = value
    return result


def main() -> int:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert registry["schema_version"] == "1.0"
    profiles = {
        item["profile_id"]: item for item in registry["profiles"]
    }
    assert set(profiles) == {
        "codestra-middleware-staging-v1",
        "codestra-middleware-production-v1",
        "codestra-middleware-production-compose-v1",
    }

    staging = profiles["codestra-middleware-staging-v1"]
    production = profiles["codestra-middleware-production-v1"]
    compose = profiles["codestra-middleware-production-compose-v1"]
    assert staging["profile_id"] == "codestra-middleware-staging-v1"
    assert production["profile_id"] == "codestra-middleware-production-v1"
    assert staging["production_activation_allowed"] is False
    assert production["production_activation_allowed"] is True
    assert compose["environment"] == "production"
    assert compose["production_activation_allowed"] is False

    for profile in (staging, production):
        environment = profile["environment"]
        marker = f"middleware-{environment}"
        assert marker in profile["database"]["host"]
        assert environment in profile["database"]["name"]
        assert environment in profile["database"]["username"]
        assert marker in profile["redis"]["host"]
        assert environment in profile["redis"]["username"]
        assert marker in profile["nats"]["host"]
        assert marker in profile["temporal"]["address"]
        assert environment in profile["temporal"]["namespace"]
        assert environment in profile["temporal"]["task_queue"]
        assert f"middleware-{environment}-" in profile["secret_path_prefix"]

        template = load_env(
            ROOT
            / "config"
            / "environments"
            / f"{environment}.runtime.env.example"
        )
        assert template["APP_ENV"] == environment
        assert template["RUNTIME_PROFILE_ID"] == profile["profile_id"]
        assert all(template.get(flag) == "false" for flag in EFFECT_FLAGS)
        assert template["PRODUCTION_DIALING"] == "DISABLED"

    compose_template = load_env(
        ROOT / "config/environments/production-compose.runtime.env.example"
    )
    assert compose_template["APP_ENV"] == "production"
    assert compose_template["RUNTIME_PROFILE_ID"] == compose["profile_id"]
    assert compose["database"] == {
        "scheme": "postgresql",
        "host": "codestra-postgres-1",
        "port": 5432,
        "name": "codestra_middleware_appolon",
        "username": "appolon_middleware_api",
        "sslmode": None,
    }
    assert compose["redis"] == {
        "scheme": "redis",
        "host": "redis",
        "port": 6379,
        "database": 0,
        "username": "middleware-service",
    }
    assert all(compose_template.get(flag) == "false" for flag in EFFECT_FLAGS)
    assert compose_template["NATS_DISPATCH_MODE"] == "disabled"
    assert compose_template["TEMPORAL_WORKER_MODE"] == "disabled"
    assert compose_template["PRODUCTION_DIALING"] == "DISABLED"

    assert staging["database"] != production["database"]
    assert staging["redis"] != production["redis"]
    assert staging["nats"] != production["nats"]
    assert staging["temporal"] != production["temporal"]
    print("RUNTIME_ENVIRONMENT_PROFILES=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
