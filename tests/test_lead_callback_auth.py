import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

import app.api.v1.lead_automation as lead_api
from app.core.lead_callback_auth import (
    AUDIENCE,
    CALLBACK_SCOPE,
    CALLBACK_METHOD,
    CALLBACK_PATH,
    IDENTITY,
    SIGNATURE_VERSION,
    CallbackAuthenticationError,
    canonical_callback_material,
    sign_callback,
    verify_callback,
)
from app.main import app

BODY = b'{"environment":"staging","synthetic":true}'
SECRET = b"synthetic-callback-test-secret"
NOW = datetime(2026, 1, 1, tzinfo=UTC)
TIMESTAMP = NOW.isoformat()
NONCE = "synthetic-callback-nonce"
IDEMPOTENCY_KEY = "d" * 64


def headers(body: bytes = BODY, **overrides: str) -> dict[str, str]:
    value = sign_callback(
        body=body,
        secret=SECRET,
        timestamp=TIMESTAMP,
        nonce=NONCE,
        idempotency_key=IDEMPOTENCY_KEY,
        environment="staging",
    )
    value.update(overrides)
    return value


def verify(
    *,
    body: bytes = BODY,
    value: dict[str, str] | None = None,
    method: str = CALLBACK_METHOD,
    path: str = CALLBACK_PATH,
    query_string: bytes = b"",
    now: datetime = NOW,
    used: set[tuple[str, str, str, str]] | None = None,
) -> None:
    verify_callback(
        method=method,
        path=path,
        query_string=query_string,
        body=body,
        headers=value or headers(body),
        secret=SECRET,
        environment="staging",
        used_nonces=used if used is not None else set(),
        now=now,
    )


def test_valid_exact_post_path_and_body_are_accepted():
    verify()


def test_canonical_material_is_exactly_hmac_v2_without_terminal_newline():
    body_hash = hashlib.sha256(BODY).hexdigest()
    expected = (
        f"{SIGNATURE_VERSION}\nPOST\n{CALLBACK_PATH}\n{TIMESTAMP}\n{NONCE}\n"
        f"{IDENTITY}\n{AUDIENCE}\nstaging\n{CALLBACK_SCOPE}\n"
        f"{IDEMPOTENCY_KEY}\n{body_hash}"
    ).encode("ascii")
    actual = canonical_callback_material(
        signature_version=SIGNATURE_VERSION,
        method=CALLBACK_METHOD,
        path=CALLBACK_PATH,
        timestamp=TIMESTAMP,
        nonce=NONCE,
        service_identity=IDENTITY,
        service_audience=AUDIENCE,
        environment="staging",
        scope=CALLBACK_SCOPE,
        idempotency_key=IDEMPOTENCY_KEY,
        body_sha256=body_hash,
    )
    assert actual == expected
    assert actual.count(b"\n") == 10 and not actual.endswith(b"\n")


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", ""])
def test_wrong_method_with_post_signature_is_denied(method):
    with pytest.raises(CallbackAuthenticationError, match="method"):
        verify(method=method)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/lead-automation/other",
        CALLBACK_PATH + "/",
        "/api/v1/lead-automation/%72esults",
        "",
    ],
)
def test_wrong_trailing_encoded_or_empty_path_is_denied(path):
    with pytest.raises(CallbackAuthenticationError, match="path"):
        verify(path=path)


def test_query_string_is_denied():
    with pytest.raises(CallbackAuthenticationError, match="query"):
        verify(query_string=b"next=other")


def test_method_and_path_changes_alter_signatures():
    original = headers()["X-Codestra-Signature"]
    changed_method = sign_callback(
        body=BODY,
        secret=SECRET,
        timestamp=TIMESTAMP,
        nonce=NONCE,
        idempotency_key=IDEMPOTENCY_KEY,
        environment="staging",
        method="PUT",
    )["X-Codestra-Signature"]
    changed_path = sign_callback(
        body=BODY,
        secret=SECRET,
        timestamp=TIMESTAMP,
        nonce=NONCE,
        idempotency_key=IDEMPOTENCY_KEY,
        environment="staging",
        path="/api/v1/lead-automation/other",
    )["X-Codestra-Signature"]
    assert len({original, changed_method, changed_path}) == 3


def test_body_changed_after_signing_is_denied():
    with pytest.raises(CallbackAuthenticationError, match="body hash"):
        verify(body=b'{"environment":"staging","synthetic":false}', value=headers())


@pytest.mark.parametrize(
    ("header", "replacement", "message"),
    [
        ("Idempotency-Key", "e" * 64, "signature"),
        ("X-Codestra-Timestamp", (NOW + timedelta(seconds=1)).isoformat(), "signature"),
        ("X-Codestra-Nonce", "different-nonce", "signature"),
        ("X-Service-Identity", "wrong-identity", "identity"),
        ("X-Service-Audience", "wrong-audience", "identity"),
        ("X-Codestra-Environment", "production", "environment"),
        ("X-Codestra-Scope", "lead-automation.registration.write", "scope"),
        ("X-Codestra-Scope", "lead-automation.acknowledgements.write", "scope"),
        ("X-Codestra-Scope", "*", "scope"),
    ],
)
def test_bound_header_tampering_is_denied(header, replacement, message):
    value = headers()
    value[header] = replacement
    with pytest.raises(CallbackAuthenticationError, match=message):
        verify(value=value)


@pytest.mark.parametrize(
    "now",
    [NOW + timedelta(seconds=301), NOW - timedelta(seconds=301)],
)
def test_expired_or_future_timestamp_is_denied(now):
    with pytest.raises(CallbackAuthenticationError, match="expired"):
        verify(now=now)


def test_reused_nonce_is_denied():
    used: set[tuple[str, str, str, str]] = set()
    verify(used=used)
    with pytest.raises(CallbackAuthenticationError, match="reused"):
        verify(used=used)


def test_missing_and_invalid_signature_are_denied():
    missing = headers()
    missing.pop("X-Codestra-Signature")
    with pytest.raises(CallbackAuthenticationError, match="missing"):
        verify(value=missing)
    invalid = headers(**{"X-Codestra-Signature": "0" * 64})
    with pytest.raises(CallbackAuthenticationError, match="invalid"):
        verify(value=invalid)


@pytest.mark.parametrize(
    "header", ["X-Codestra-Signature-Version", "X-Codestra-Scope"]
)
def test_missing_version_or_scope_is_denied(header):
    value = headers()
    value.pop(header)
    with pytest.raises(CallbackAuthenticationError, match="missing"):
        verify(value=value)


@pytest.mark.parametrize("version", ["HMAC-V1", "HMAC-V3", "*"])
def test_unsupported_or_legacy_signature_version_is_denied(version):
    value = headers(**{"X-Codestra-Signature-Version": version})
    with pytest.raises(CallbackAuthenticationError, match="version"):
        verify(value=value)


@pytest.mark.parametrize("scope", ["", "*", "lead-automation.registration.write"])
def test_empty_wildcard_or_cross_capability_scope_is_denied(scope):
    value = headers(**{"X-Codestra-Scope": scope})
    with pytest.raises(CallbackAuthenticationError, match="missing|scope"):
        verify(value=value)


@pytest.mark.parametrize("body_hash", ["A" * 64, "0" * 63, "not-hex"])
def test_invalid_body_hash_format_is_denied(body_hash):
    value = headers(**{"X-Codestra-Content-SHA256": body_hash})
    with pytest.raises(CallbackAuthenticationError, match="format"):
        verify(value=value)


def test_newline_in_signing_material_is_denied():
    with pytest.raises(CallbackAuthenticationError, match="material"):
        canonical_callback_material(
            signature_version=SIGNATURE_VERSION,
            method="POST",
            path=CALLBACK_PATH,
            timestamp=TIMESTAMP,
            nonce="bad\nnonce",
            service_identity=IDENTITY,
            service_audience=AUDIENCE,
            environment="staging",
            scope=CALLBACK_SCOPE,
            idempotency_key=IDEMPOTENCY_KEY,
            body_sha256=hashlib.sha256(BODY).hexdigest(),
        )


def test_duplicate_authentication_headers_are_denied_before_result_processing(
    monkeypatch,
):
    processed = 0

    def must_not_process(_body, _scope):
        nonlocal processed
        processed += 1
        raise AssertionError("result processing must not run")

    monkeypatch.setattr(lead_api.service, "receive_result", must_not_process)
    monkeypatch.setattr(lead_api.settings, "lead_automation_hmac_secret", SECRET.decode())
    client = TestClient(app)
    duplicated = list(headers().items()) + [("X-Service-Identity", IDENTITY)]
    response = client.post(CALLBACK_PATH, content=BODY, headers=duplicated)
    assert response.status_code == 401
    assert processed == 0


def test_route_authentication_rejection_causes_no_state_transition(monkeypatch):
    processed = 0

    def must_not_process(_body, _scope):
        nonlocal processed
        processed += 1
        raise AssertionError("result processing must not run")

    monkeypatch.setattr(lead_api.service, "receive_result", must_not_process)
    monkeypatch.setattr(lead_api.settings, "lead_automation_hmac_secret", SECRET.decode())
    client = TestClient(app)
    invalid = deepcopy(headers())
    invalid["X-Codestra-Signature"] = "0" * 64
    response = client.post(CALLBACK_PATH, content=BODY, headers=invalid)
    assert response.status_code == 401
    assert processed == 0


def test_method_override_header_does_not_change_signed_method(monkeypatch):
    processed = 0

    def process(_body, _scope):
        nonlocal processed
        processed += 1
        return {"accepted": True}

    monkeypatch.setattr(lead_api.service, "receive_result", process)
    monkeypatch.setattr(lead_api.settings, "lead_automation_hmac_secret", SECRET.decode())
    client = TestClient(app)
    current_headers = sign_callback(
        body=BODY,
        secret=SECRET,
        timestamp=datetime.now(UTC).isoformat(),
        nonce="method-override-current-nonce",
        idempotency_key=IDEMPOTENCY_KEY,
        environment="staging",
    )
    response = client.post(
        CALLBACK_PATH,
        content=BODY,
        headers={**current_headers, "X-HTTP-Method-Override": "DELETE"},
    )
    assert response.status_code == 200
    assert processed == 1
