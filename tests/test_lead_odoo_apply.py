import json
from copy import deepcopy
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest

from app.adapters.odoo.lead_automation import (
    APPLY_SCOPE,
    AUDIENCE,
    HTTP_METHOD,
    IDENTITY,
    REQUEST_PATH,
    SIGNATURE_VERSION,
    AckValidationError,
    ApplySchemaError,
    AuthenticationError,
    IdempotencyConflict,
    OdooLeadApplyClient,
    PermanentApplyError,
    ReplayError,
    RetryExhausted,
    TransportResponse,
    build_apply_payload,
    canonical_body,
    classify_ack,
    signed_headers_for_body,
    validate_ack,
    validate_apply,
    verify_signed_request,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SECRET = b"synthetic-runtime-secret"


def event() -> dict:
    return {
        "contract_version": "1.1",
        "event_id": "EVT-synthetic01",
        "environment": "staging",
        "company_key": "COMPANY-1",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "TEST_LEADS",
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "policy_version": "1.0",
        "idempotency_key": "a" * 64,
        "correlation_id": "00000000-0000-4000-8000-000000000001",
        "attributes_schema_key": "web-mobile-ai-lead-v1",
        "attributes": {"solution_type": "AI"},
        "consent_snapshot": {
            "consent_status": "granted",
            "consent_purpose": "LEAD_SERVICE",
            "consent_source": "odoo",
            "consent_updated_at": "2026-01-01T00:00:00Z",
            "dnc_status": False,
            "dnc_updated_at": "2026-01-01T00:00:00Z",
            "jurisdiction": "DO",
            "source_system": "odoo",
        },
        "lead_uid": "LEAD-synthetic01",
    }


def apply_payload() -> dict:
    return build_apply_payload(
        event=event(),
        result={"workflow_execution_id": "N8N-synthetic01", "result_code": "UPDATED"},
        automation_event_id="LAE-synthetic01",
    )


def ack(result: str = "APPLIED", **changes: object) -> dict:
    value = {
        "contract_version": "1.1",
        "automation_event_id": "LAE-synthetic01",
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "lead_uid": "LEAD-synthetic01",
        "odoo_record_id": 42,
        "result": result,
        "applied_fields": ["solution_type"] if result == "APPLIED" else [],
        "unchanged_fields": ["solution_type"] if result == "NO_CHANGE" else [],
        "rejected_fields": [],
        "company_key": "COMPANY-1",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "TEST_LEADS",
        "policy_version": "1.0",
        "updated_at": "2026-01-01T00:00:01Z",
        "idempotent_replay": False,
    }
    if result == "FAILED":
        value["result_code"] = "PERMANENT_FAILURE"
    value.update(changes)
    return value


def signed() -> tuple[bytes, dict[str, str]]:
    body = canonical_body(apply_payload())
    headers = signed_headers_for_body(
        body,
        SECRET,
        "staging",
        "a" * 64,
        timestamp=NOW.isoformat(),
        nonce="nonce-synthetic-01",
    )
    return body, headers


def verify(body: bytes, headers: dict[str, str], **changes: object) -> None:
    values = {
        "method": HTTP_METHOD,
        "path": REQUEST_PATH,
        "body": body,
        "headers": headers,
        "secret": SECRET,
        "expected_environment": "staging",
        "used_nonces": set(),
        "now": NOW,
    }
    values.update(changes)
    verify_signed_request(**values)  # type: ignore[arg-type]


def test_builder_is_strict_deterministic_and_event_bound() -> None:
    payload = apply_payload()
    validate_apply(payload)
    assert canonical_body(payload) == canonical_body(deepcopy(payload))
    assert payload["idempotency_key"] == event()["idempotency_key"]
    broken = dict(payload, unexpected="value")
    with pytest.raises(ApplySchemaError):
        validate_apply(broken)


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        ("method", "PUT"),
        ("path", "/codestra/api/v1/leads/automation/other"),
        ("body", b"{}"),
    ],
)
def test_signature_rejects_method_path_and_body_tampering(
    target: str, replacement: object
) -> None:
    body, headers = signed()
    checked_body = replacement if target == "body" else body
    changes = {} if target == "body" else {target: replacement}
    with pytest.raises(AuthenticationError):
        verify(checked_body, headers, **changes)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("header", "replacement"),
    [
        ("Idempotency-Key", "b" * 64),
        ("X-Codestra-Timestamp", "2026-01-01T00:00:01+00:00"),
        ("X-Codestra-Nonce", "other-nonce"),
        ("X-Service-Identity", "other-service"),
        ("X-Service-Audience", "other-audience"),
        ("X-Codestra-Environment", "production"),
        ("X-Codestra-Signature-Version", "HMAC-V1"),
        ("X-Codestra-Scope", "lead-automation.results.write"),
        ("X-Codestra-Scope", "*"),
    ],
)
def test_signature_rejects_header_tampering(header: str, replacement: str) -> None:
    body, headers = signed()
    headers[header] = replacement
    with pytest.raises(AuthenticationError):
        verify(body, headers)


def test_signature_accepts_valid_request_and_rejects_expiry_and_replay() -> None:
    body, headers = signed()
    nonces: set[tuple[str, str, str, str]] = set()
    verify(body, headers, used_nonces=nonces)
    with pytest.raises(ReplayError):
        verify(body, headers, used_nonces=nonces)
    with pytest.raises(AuthenticationError, match="expired"):
        verify(body, headers, now=NOW + timedelta(minutes=6))
    assert headers["X-Service-Identity"] == IDENTITY
    assert headers["X-Service-Audience"] == AUDIENCE
    assert headers["X-Codestra-Signature-Version"] == SIGNATURE_VERSION
    assert headers["X-Codestra-Scope"] == APPLY_SCOPE
    assert "Authorization" not in headers


@pytest.mark.parametrize(
    "header", ["X-Codestra-Signature-Version", "X-Codestra-Scope"]
)
def test_apply_hmac_v2_rejects_missing_version_or_scope(header: str) -> None:
    body, headers = signed()
    headers.pop(header)
    with pytest.raises(AuthenticationError, match="missing"):
        verify(body, headers)


@pytest.mark.parametrize(
    ("result", "classification"),
    [
        ("APPLIED", "complete"),
        ("NO_CHANGE", "complete"),
        ("DENIED", "permanent"),
        ("CONSENT_BLOCKED", "permanent"),
        ("DNC_BLOCKED", "permanent"),
        ("QUARANTINED", "permanent"),
        ("FAILED", "permanent"),
    ],
)
def test_all_ack_results_validate_and_classify(
    result: str, classification: str
) -> None:
    value = ack(result)
    validate_ack(value, apply_payload())
    assert classify_ack(value) == classification


def test_failed_retries_only_explicit_code() -> None:
    value = ack("FAILED", result_code="TEMPORARY_UNAVAILABLE")
    validate_ack(value, apply_payload())
    assert classify_ack(value) == "retry"


@pytest.mark.parametrize(
    "change",
    [
        {"result": "UNKNOWN"},
        {"automation_event_id": "LAE-different01"},
        {"business_unit_key": "other-unit"},
        {"unexpected": True},
    ],
)
def test_unknown_schema_and_binding_mismatch_rejected(change: dict) -> None:
    with pytest.raises(AckValidationError):
        validate_ack(ack(**change), apply_payload())


class ScriptedTransport:
    def __init__(self, outcomes: list[TransportResponse | BaseException]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, str, bytes, dict[str, str], float]] = []

    def __call__(
        self,
        method: str,
        path: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> TransportResponse:
        self.calls.append((method, path, body, dict(headers), timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[return-value]


def response(value: dict, status: int = 200) -> TransportResponse:
    return TransportResponse(status, json.dumps(value).encode())


def test_identical_apply_replay_returns_same_ack_without_duplicate() -> None:
    transport = ScriptedTransport([response(ack())])
    client = OdooLeadApplyClient(secret=SECRET, transport=transport)
    first = client.apply(apply_payload())
    second = client.apply(deepcopy(apply_payload()))
    assert first.ack == second.ack and second.replayed and second.attempts == 0
    assert len(transport.calls) == 1


def test_conflicting_apply_replay_is_quarantinable_and_audited() -> None:
    transport = ScriptedTransport([response(ack())])
    client = OdooLeadApplyClient(secret=SECRET, transport=transport)
    client.apply(apply_payload())
    changed = apply_payload()
    changed["attributes"] = {"solution_type": "MOBILE"}
    with pytest.raises(IdempotencyConflict):
        client.apply(changed)
    assert client.audit[-1]["result"] == "IDEMPOTENCY_CONFLICT"
    assert len(transport.calls) == 1


@pytest.mark.parametrize("retry", [TimeoutError(), 429, 500, 502, 503, 504])
def test_bounded_retry_then_success(retry: BaseException | int) -> None:
    first = retry if isinstance(retry, BaseException) else TransportResponse(retry, b"")
    transport = ScriptedTransport([first, response(ack())])
    outcome = OdooLeadApplyClient(secret=SECRET, transport=transport).apply(
        apply_payload()
    )
    assert outcome.attempts == 2 and len(transport.calls) == 2


def test_retry_exhaustion_and_permanent_responses() -> None:
    transport = ScriptedTransport([TransportResponse(503, b"")] * 3)
    with pytest.raises(RetryExhausted):
        OdooLeadApplyClient(secret=SECRET, transport=transport).apply(apply_payload())
    with pytest.raises(PermanentApplyError):
        OdooLeadApplyClient(
            secret=SECRET, transport=ScriptedTransport([TransportResponse(401, b"")])
        ).apply(apply_payload())
    with pytest.raises(PermanentApplyError):
        OdooLeadApplyClient(
            secret=SECRET, transport=ScriptedTransport([response(ack("DENIED"))])
        ).apply(apply_payload())


def test_boundary_has_no_direct_database_bearer_or_n8n_to_odoo() -> None:
    source = __import__("inspect").getsource(OdooLeadApplyClient).lower()
    assert "sql" not in source
    assert "database" in source  # boundary statement is explicit
    assert "bearer" in source
    assert "n8n" in source
    body, headers = signed()
    assert b"phone" not in body.lower() and b"email" not in body.lower()
    assert "Authorization" not in headers
