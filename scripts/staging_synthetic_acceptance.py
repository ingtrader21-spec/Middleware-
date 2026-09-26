#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid

import httpx
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SAFETY_SCHEMA = ROOT / "contracts" / "runtime-safety-readback.v1.1.schema.json"
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRODUCER = "odoo-integration"
PRODUCER_SCOPE = "odoo.events.publish"
WEBHOOK_PATH = "/api/v1/odoo/events"
EVENT_TYPE = "codestra.odoo.activity.completed"
EXPECTED_PROFILE = "codestra-middleware-staging-v1"
REQUIRED_EFFECT_CONTROLS = {
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
    "FORM_ODOO_DELIVERY_ENABLED",
    "CRAWLER_ODOO_DELIVERY_ENABLED",
    "SCRAPPER_ODOO_DELIVERY_ENABLED",
    "CRAWLER_EXTERNAL_CONTACT_ENABLED",
    "SCRAPPER_EXTERNAL_CONTACT_ENABLED",
    "SMS_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED",
    "CRAWLER_EXECUTION_ENABLED",
    "SCRAPPER_EXECUTION_ENABLED",
    "LIVE_SMS_DELIVERY",
    "LIVE_EMAIL_DELIVERY",
    "UNRESTRICTED_CRAWLING",
}
REQUIRED_UMBRELLA_CONTROLS = {
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
}


class AcceptanceError(RuntimeError):
    """Raised when deployed staging does not prove the release safety contract."""


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise AcceptanceError(f"{name} is required")
    return value


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AcceptanceError(
            "STAGING_BASE_URL must be an HTTPS origin without credentials, path, "
            "query, or fragment"
        )
    return value.rstrip("/")


def validate_runtime_safety(
    value: object,
    *,
    expected_source_sha: str,
    expected_image_digest: str,
) -> dict[str, Any]:
    schema = json.loads(SAFETY_SCHEMA.read_text(encoding="utf-8"))
    try:
        Draft202012Validator(schema).validate(value)
    except Exception as exc:
        raise AcceptanceError("runtime safety response violates its schema") from exc
    if not isinstance(value, dict):
        raise AcceptanceError("runtime safety response must be an object")
    release = value["release"]
    dispatch = value["dispatch"]
    persistence = value["persistence"]
    effects = value["external_effects"]
    umbrella_controls = value["umbrella_controls"]
    if value["environment"] != "staging":
        raise AcceptanceError("runtime is not staging")
    if value["runtime_profile_id"] != EXPECTED_PROFILE:
        raise AcceptanceError("runtime profile is not the locked staging profile")
    if release["source_sha"] != expected_source_sha:
        raise AcceptanceError("deployed source SHA does not match the approved release")
    if release["image_digest"] != expected_image_digest:
        raise AcceptanceError(
            "deployed image digest does not match the approved release"
        )
    if release["schema_head"] != "0069_agent_provisioning_rls":
        raise AcceptanceError("deployed migration head is not current")
    if persistence != {"in_memory": False}:
        raise AcceptanceError("staging must use durable persistence")
    if dispatch != {
        "outbox_enabled": False,
        "nats_mode": "disabled",
        "temporal_worker_mode": "disabled",
    }:
        raise AcceptanceError("staging dispatch planes are not fail closed")
    if set(effects) != REQUIRED_EFFECT_CONTROLS:
        raise AcceptanceError("runtime effect-control set is incomplete or unexpected")
    enabled = sorted(name for name, enabled in effects.items() if enabled)
    if enabled:
        raise AcceptanceError(
            "staging external effects are enabled: " + ", ".join(enabled)
        )
    if set(umbrella_controls) != REQUIRED_UMBRELLA_CONTROLS:
        raise AcceptanceError(
            "runtime umbrella-control set is incomplete or unexpected"
        )
    enabled_umbrella = sorted(
        name for name, enabled in umbrella_controls.items() if enabled
    )
    if enabled_umbrella:
        raise AcceptanceError(
            "staging umbrella controls are enabled: " + ", ".join(enabled_umbrella)
        )
    if value["production_dialing"] != "DISABLED":
        raise AcceptanceError("production dialing is not disabled")
    if value["production_activation_configured"] is not False:
        raise AcceptanceError("production activation is configured in staging")
    if value["all_external_effects_disabled"] is not True:
        raise AcceptanceError("runtime did not attest that all effects are disabled")
    if value["provider_effects_disabled"] is not True:
        raise AcceptanceError(
            "runtime did not attest that provider effects are disabled"
        )
    if value["staging_safe"] is not True:
        raise AcceptanceError("runtime did not attest fail-closed staging safety")
    return value


def build_signed_event(
    *,
    tenant_id: str,
    secret: bytes,
    now: int | None = None,
    event_uuid: uuid.UUID | None = None,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    generated = event_uuid or uuid.uuid4()
    event_id = f"synthetic-{generated.hex}"
    timestamp = str(int(time.time()) if now is None else now)
    occurred_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(timestamp)))
    event: dict[str, Any] = {
        "event_id": event_id,
        "event_type": EVENT_TYPE,
        "event_version": "1.0",
        "occurred_at": occurred_at,
        "received_at": occurred_at,
        "source": PRODUCER,
        "tenant_id": tenant_id,
        "correlation_id": f"corr-{generated.hex}",
        "causation_id": "staging-synthetic-acceptance",
        "idempotency_key": event_id,
        "payload": {
            "synthetic_acceptance": True,
            "external_effects_expected": False,
        },
        "metadata": {
            "test": "staging-synthetic-acceptance-v1",
        },
    }
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "v1",
            "POST",
            WEBHOOK_PATH,
            timestamp,
            event_id,
            PRODUCER,
            body_sha,
        )
    ).encode("utf-8")
    signature = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Idempotency-Key": event_id,
        "X-Codestra-Event-Id": event_id,
        "X-Codestra-Event-Type": EVENT_TYPE,
        "X-Codestra-Source": PRODUCER,
        "X-Codestra-Tenant-Id": tenant_id,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Signature": f"sha256={signature}",
        "X-Correlation-Id": event["correlation_id"],
    }
    return event, body, headers


def _json_response(response: httpx.Response, expected_status: int, label: str) -> Any:
    if response.status_code != expected_status:
        raise AcceptanceError(
            f"{label} returned HTTP {response.status_code}; expected {expected_status}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise AcceptanceError(f"{label} did not return JSON") from exc


def run(
    env: Mapping[str, str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    source = os.environ if env is None else env
    base_url = validate_base_url(_required(source, "STAGING_BASE_URL"))
    monitoring_token = _required(source, "STAGING_MONITORING_TOKEN")
    producer_token = _required(source, "STAGING_ODOO_PRODUCER_TOKEN")
    secret = _required(source, "STAGING_ODOO_WEBHOOK_SECRET").encode("utf-8")
    tenant_id = _required(source, "STAGING_SYNTHETIC_TENANT_ID")
    expected_source_sha = _required(source, "EXPECTED_SOURCE_SHA").lower()
    expected_image_digest = _required(source, "EXPECTED_IMAGE_DIGEST").lower()
    if SOURCE_SHA.fullmatch(expected_source_sha) is None:
        raise AcceptanceError("EXPECTED_SOURCE_SHA must be an exact 40-character SHA")
    if IMAGE_DIGEST.fullmatch(expected_image_digest) is None:
        raise AcceptanceError(
            "EXPECTED_IMAGE_DIGEST must be an immutable sha256 digest"
        )
    if len(secret) < 32:
        raise AcceptanceError(
            "STAGING_ODOO_WEBHOOK_SECRET must contain at least 32 bytes"
        )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None:
        raise AcceptanceError(
            "STAGING_SYNTHETIC_TENANT_ID must be a safe 1-128 character identifier"
        )

    with httpx.Client(
        base_url=base_url,
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
        transport=transport,
    ) as client:
        safety_response = client.get(
            "/v1/runtime/safety",
            headers={
                "Authorization": f"Bearer {monitoring_token}",
                "Accept": "application/json",
            },
        )
        safety = validate_runtime_safety(
            _json_response(safety_response, 200, "runtime safety read-back"),
            expected_source_sha=expected_source_sha,
            expected_image_digest=expected_image_digest,
        )
        ready = _json_response(client.get("/ready"), 200, "readiness")
        if not isinstance(ready, dict):
            raise AcceptanceError("runtime readiness response must be an object")
        components = ready.get("components")
        if (
            ready.get("status") != "ready"
            or not isinstance(components, dict)
            or not components
        ):
            raise AcceptanceError("runtime readiness is incomplete")
        if any(status != "ready" for status in components.values()):
            raise AcceptanceError(
                "one or more durable runtime dependencies are not ready"
            )
        if ready.get("release_sha") != expected_source_sha:
            raise AcceptanceError(
                "readiness source SHA disagrees with the approved release"
            )
        if ready.get("image_digest") != expected_image_digest:
            raise AcceptanceError(
                "readiness image digest disagrees with the approved release"
            )

        event, body, signed_headers = build_signed_event(
            tenant_id=tenant_id,
            secret=secret,
        )
        signed_headers["Authorization"] = f"Bearer {producer_token}"
        first = _json_response(
            client.post(WEBHOOK_PATH, content=body, headers=signed_headers),
            202,
            "synthetic acceptance",
        )
        duplicate = _json_response(
            client.post(WEBHOOK_PATH, content=body, headers=signed_headers),
            200,
            "synthetic duplicate",
        )
        if not isinstance(first, dict) or (
            first.get("event_id") != event["event_id"]
            or first.get("tenant_id") != tenant_id
            or first.get("status") != "accepted"
            or first.get("duplicate") is not False
        ):
            raise AcceptanceError("first synthetic result is not canonical acceptance")
        if not isinstance(duplicate, dict) or (
            duplicate.get("event_id") != event["event_id"]
            or duplicate.get("tenant_id") != tenant_id
            or duplicate.get("status") != "duplicate"
            or duplicate.get("duplicate") is not True
        ):
            raise AcceptanceError("synthetic retry was not reconciled as a duplicate")

    return {
        "status": "passed",
        "service": safety["service"],
        "environment": safety["environment"],
        "runtime_profile_id": safety["runtime_profile_id"],
        "source_sha": expected_source_sha,
        "image_digest": expected_image_digest,
        "schema_head": safety["release"]["schema_head"],
        "synthetic_event_id": event["event_id"],
        "checks": [
            "runtime-safety-readback",
            "durable-dependency-readiness",
            "signed-event-acceptance",
            "idempotent-duplicate",
        ],
    }


def main() -> None:
    try:
        result = run()
    except (AcceptanceError, httpx.HTTPError, OSError) as exc:
        print(f"STAGING_SYNTHETIC_ACCEPTANCE=FAIL reason={exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    print("STAGING_SYNTHETIC_ACCEPTANCE=PASS")


if __name__ == "__main__":
    main()
