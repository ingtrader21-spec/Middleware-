from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CallbackCertificationError(ValueError):
    pass


@dataclass(frozen=True)
class CallbackPreflight:
    path: str
    mtls: bool
    required_headers: tuple[str, ...]
    live_effects: int
    provider_effects: int


_REQUIRED_HEADERS = {
    "Authorization",
    "X-Event-Id",
    "X-Timestamp",
    "X-Signature",
    "Idempotency-Key",
    "Content-Type: application/json",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_callback_preflight(repo_root: str | Path) -> CallbackPreflight:
    root = Path(repo_root)
    ingress = _load(root / "config" / "telnexa-event-ingress.v1.json")
    source_lock = _load(root / "config" / "telnexa-sms-provider-source-lock.v1.json")

    if ingress.get("method") != "POST" or ingress.get("path") != "/api/v1/events/telnexa":
        raise CallbackCertificationError("canonical Telnexa callback route mismatch")

    transport = ingress.get("transport") or {}
    if transport.get("tls") != "mTLS":
        raise CallbackCertificationError("callback transport must require mTLS")
    if transport.get("redirects_allowed") is not False:
        raise CallbackCertificationError("callback redirects must be disabled")

    auth = ingress.get("authentication") or {}
    if auth.get("algorithm") != "HMAC-SHA256":
        raise CallbackCertificationError("callback signature algorithm mismatch")
    ttl = int(auth.get("freshness_ttl_seconds") or 0)
    if ttl <= 0 or ttl > 300:
        raise CallbackCertificationError("callback freshness TTL must be 1..300 seconds")

    headers = set(ingress.get("required_headers") or [])
    missing = sorted(_REQUIRED_HEADERS - headers)
    if missing:
        raise CallbackCertificationError("missing required headers: " + ",".join(missing))

    delivery = ingress.get("delivery") or {}
    expected_responses = {
        "duplicate_response": 200,
        "new_event_response": 202,
        "retryable_persistence_response": 503,
        "mismatched_replay_response": 409,
    }
    for key, expected in expected_responses.items():
        if delivery.get(key) != expected:
            raise CallbackCertificationError(f"{key} must be {expected}")
    if delivery.get("mode") != "at_least_once":
        raise CallbackCertificationError("delivery mode must remain at_least_once")

    projection = ingress.get("projection") or {}
    if projection.get("terminal_statuses_are_sticky") is not True:
        raise CallbackCertificationError("terminal statuses must remain sticky")
    if projection.get("missing_message_is_retryable") is not True:
        raise CallbackCertificationError("missing messages must remain retryable")

    gates = ingress.get("activation_gates") or {}
    if gates.get("default") is not False:
        raise CallbackCertificationError("callback activation must default off")

    live_effects = source_lock.get("liveEffects") or {}
    enabled = [key for key, value in live_effects.items() if value not in (False, 0, "false", "NO")]
    if enabled:
        raise CallbackCertificationError("live effects must remain disabled: " + ",".join(enabled))

    return CallbackPreflight(
        path=ingress["path"],
        mtls=True,
        required_headers=tuple(sorted(headers)),
        live_effects=0,
        provider_effects=0,
    )
