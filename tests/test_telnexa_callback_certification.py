from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.platform.telnexa_callback_certification import (
    CallbackCertificationError,
    validate_callback_preflight,
)


ROOT = Path(__file__).resolve().parents[1]


def test_repository_callback_contract_is_fail_closed() -> None:
    result = validate_callback_preflight(ROOT)
    assert result.path == "/api/v1/events/telnexa"
    assert result.mtls is True
    assert result.live_effects == 0
    assert result.provider_effects == 0
    assert "X-Signature" in result.required_headers


def _copy(root: Path) -> None:
    for relative in (
        "config/telnexa-event-ingress.v1.json",
        "config/telnexa-sms-provider-source-lock.v1.json",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())


def test_missing_signature_header_is_rejected(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["required_headers"].remove("X-Signature")
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="missing required headers"):
        validate_callback_preflight(tmp_path)


def test_live_sms_effect_is_rejected(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-sms-provider-source-lock.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["liveEffects"]["SMS_DELIVERY"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="live effects must remain disabled"):
        validate_callback_preflight(tmp_path)


def test_callback_requires_mtls_and_no_redirects(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["transport"]["tls"] = "TLS"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="mTLS"):
        validate_callback_preflight(tmp_path)

    _copy(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["transport"]["redirects_allowed"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="redirects"):
        validate_callback_preflight(tmp_path)


@pytest.mark.parametrize("ttl", [0, 301, "not-an-int"])
def test_callback_freshness_ttl_is_bounded_and_typed(tmp_path, ttl) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["authentication"]["freshness_ttl_seconds"] = ttl
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="freshness TTL"):
        validate_callback_preflight(tmp_path)


def test_duplicate_required_header_is_rejected(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["required_headers"].append("X-Signature")
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="must be unique"):
        validate_callback_preflight(tmp_path)


def test_delivery_semantics_are_pinned(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["delivery"]["mismatched_replay_response"] = 202
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="mismatched_replay_response"):
        validate_callback_preflight(tmp_path)


def test_activation_gate_set_cannot_silently_shrink(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["activation_gates"]["required"].remove(
        "TELNEXA_EVENT_HMAC_SECRET or TELNEXA_EVENT_HMAC_SECRET_FILE"
    )
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="gate set drift"):
        validate_callback_preflight(tmp_path)


def test_provider_credentials_must_remain_separate(tmp_path) -> None:
    _copy(tmp_path)
    path = tmp_path / "config" / "telnexa-event-ingress.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["activation_gates"]["provider_credentials_are_separate"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CallbackCertificationError, match="credentials must remain separate"):
        validate_callback_preflight(tmp_path)
