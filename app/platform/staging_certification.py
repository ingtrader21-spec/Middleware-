from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class StagingCertificationError(ValueError):
    pass


@dataclass(frozen=True)
class StagingPreflight:
    profile_id: str
    campaign: str
    listener_port: int
    direct_effect_bypasses: int
    provider_effects: int


_FALSE_FLAGS = (
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
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
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            raise StagingCertificationError(f"invalid env line: {raw!r}")
        if key in values:
            raise StagingCertificationError(f"duplicate env key: {key}")
        values[key] = value.strip()
    return values


def validate_staging_preflight(repo_root: str | Path) -> StagingPreflight:
    root = Path(repo_root)
    env = _load_env(root / "config" / "environments" / "staging.runtime.env.example")
    safety = _load_json(root / "config" / "platform-safety.v1.json")
    routes = _load_json(root / "config" / "route-authority-report.v1.json")

    required = {
        "APP_ENV": "staging",
        "RUNTIME_PROFILE_ID": "codestra-middleware-staging-v1",
        "NATS_DISPATCH_MODE": "disabled",
        "TEMPORAL_WORKER_MODE": "disabled",
        "PRODUCTION_DIALING": "DISABLED",
    }
    for key, expected in required.items():
        if env.get(key) != expected:
            raise StagingCertificationError(f"{key} must be {expected!r}")

    for key in _FALSE_FLAGS:
        if env.get(key, "").lower() != "false":
            raise StagingCertificationError(f"{key} must remain false")

    if safety.get("synthetic_tenants") != ["TEST_SYN"]:
        raise StagingCertificationError("staging synthetic tenant must be TEST_SYN only")

    gate = (safety.get("capability_gates") or {}).get("TEST_SYN_EXECUTE") or {}
    if gate.get("classification") != "synthetic":
        raise StagingCertificationError("TEST_SYN_EXECUTE must remain synthetic")
    if gate.get("synthetic_tenant_required") is not True:
        raise StagingCertificationError("TEST_SYN_EXECUTE must require synthetic tenant")
    if not {"staging", "preproduction"}.issubset(set(gate.get("environments") or [])):
        raise StagingCertificationError("TEST_SYN_EXECUTE missing staging/preproduction")

    if routes.get("service") != "middleware-integration-api":
        raise StagingCertificationError("canonical integration service mismatch")
    if routes.get("listener_port") != 8095:
        raise StagingCertificationError("canonical Middleware port must be 8095")
    bypasses = int((routes.get("summary") or {}).get("DIRECT_EFFECT_BYPASSES", -1))
    if bypasses != 0:
        raise StagingCertificationError("direct effect bypasses must be zero")

    certifier = root / "scripts" / "certify_test_syn.py"
    if not certifier.is_file():
        raise StagingCertificationError("TEST_SYN certifier missing")
    if "legacy port 8080" not in certifier.read_text(encoding="utf-8"):
        raise StagingCertificationError("TEST_SYN certifier must reject legacy port 8080")

    return StagingPreflight(
        profile_id=env["RUNTIME_PROFILE_ID"],
        campaign="TEST_SYN",
        listener_port=8095,
        direct_effect_bypasses=0,
        provider_effects=0,
    )
