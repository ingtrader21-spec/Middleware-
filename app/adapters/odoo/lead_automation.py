from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

HTTP_METHOD = "POST"
REQUEST_PATH = "/codestra/api/v1/leads/automation/apply"
IDENTITY = "codestra-middleware"
AUDIENCE = "codestra-odoo-lead-automation-api"
SIGNATURE_VERSION = "HMAC-V2"
APPLY_SCOPE = "lead-automation.odoo-apply.write"
ENVIRONMENTS = frozenset({"test", "staging", "production"})
ACTIONS = frozenset(
    {
        "CREATE_LEAD",
        "UPDATE_ALLOWLISTED_FIELDS",
        "ASSIGN_AUTHORIZED_TEAM",
        "ASSIGN_AUTHORIZED_USER",
        "CHANGE_AUTHORIZED_STAGE",
        "CREATE_INTERNAL_CALLBACK_ACTIVITY",
    }
)
ACK_RESULTS = frozenset(
    {
        "APPLIED",
        "NO_CHANGE",
        "DENIED",
        "CONSENT_BLOCKED",
        "DNC_BLOCKED",
        "QUARANTINED",
        "FAILED",
    }
)
RETRYABLE_RESULT_CODES = frozenset(
    {"TEMPORARY_UNAVAILABLE", "ODOO_TEMPORARY_UNAVAILABLE"}
)
RETRYABLE_HTTP_STATUS = frozenset({429, 500, 502, 503, 504})
REQUIRED_APPLY_FIELDS = frozenset(
    {
        "contract_version",
        "automation_event_id",
        "idempotency_key",
        "environment",
        "company_key",
        "business_unit_key",
        "campaign_key",
        "automation_action",
        "policy_version",
        "correlation_id",
        "attributes_schema_key",
        "attributes",
        "consent_snapshot",
        "workflow_execution_id",
        "result_code",
    }
)
OPTIONAL_APPLY_FIELDS = frozenset({"lead_uid", "source_reference"})
REQUIRED_ACK_FIELDS = frozenset(
    {
        "contract_version",
        "automation_event_id",
        "automation_action",
        "lead_uid",
        "odoo_record_id",
        "result",
        "applied_fields",
        "unchanged_fields",
        "rejected_fields",
        "company_key",
        "business_unit_key",
        "campaign_key",
        "policy_version",
        "updated_at",
        "idempotent_replay",
    }
)
ACK_OPTIONAL_FIELDS = frozenset({"result_code"})
HEADER_NAMES = (
    "X-Codestra-Signature-Version",
    "X-Service-Identity",
    "X-Service-Audience",
    "X-Codestra-Timestamp",
    "X-Codestra-Nonce",
    "X-Codestra-Content-SHA256",
    "X-Codestra-Signature",
    "Idempotency-Key",
    "X-Codestra-Environment",
    "X-Codestra-Scope",
)


class OdooApplyError(ValueError):
    """Base class for fail-closed Odoo apply errors."""


class ApplySchemaError(OdooApplyError):
    pass


class AckValidationError(OdooApplyError):
    pass


class AuthenticationError(OdooApplyError):
    pass


class ReplayError(AuthenticationError):
    pass


class IdempotencyConflict(OdooApplyError):
    pass


class PermanentApplyError(OdooApplyError):
    pass


class RetryExhausted(OdooApplyError):
    pass


def canonical_body(payload: Mapping[str, Any]) -> bytes:
    """Return the one exact JSON representation used for hashing and transport."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signing_material(
    signature_version: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    service_identity: str,
    service_audience: str,
    environment: str,
    scope: str,
    idempotency_key: str,
    body_hash: str,
) -> bytes:
    values = (
        signature_version,
        method,
        path,
        timestamp,
        nonce,
        service_identity,
        service_audience,
        environment,
        scope,
        idempotency_key,
        body_hash,
    )
    if any(not value or "\n" in value or "\r" in value for value in values):
        raise AuthenticationError("invalid signing material")
    return "\n".join(values).encode("ascii")


def signed_headers_for_body(
    body: bytes,
    secret: bytes,
    environment: str,
    idempotency_key: str,
    *,
    method: str = HTTP_METHOD,
    path: str = REQUEST_PATH,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    if method != HTTP_METHOD or path != REQUEST_PATH:
        raise AuthenticationError("method or path outside Odoo apply contract")
    if environment not in ENVIRONMENTS:
        raise AuthenticationError("invalid environment")
    timestamp = timestamp or datetime.now(UTC).isoformat()
    nonce = nonce or str(uuid4())
    body_hash = _sha256(body)
    signature = hmac.new(
        secret,
        signing_material(
            SIGNATURE_VERSION,
            method,
            path,
            timestamp,
            nonce,
            IDENTITY,
            AUDIENCE,
            environment,
            APPLY_SCOPE,
            idempotency_key,
            body_hash,
        ),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Codestra-Signature-Version": SIGNATURE_VERSION,
        "X-Service-Identity": IDENTITY,
        "X-Service-Audience": AUDIENCE,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Content-SHA256": body_hash,
        "X-Codestra-Signature": signature,
        "Idempotency-Key": idempotency_key,
        "X-Codestra-Environment": environment,
        "X-Codestra-Scope": APPLY_SCOPE,
        "Content-Type": "application/json",
    }


def signed_headers(
    payload: dict[str, Any],
    secret: bytes,
    environment: str,
    idempotency_key: str,
    *,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    return signed_headers_for_body(
        canonical_body(payload),
        secret,
        environment,
        idempotency_key,
        timestamp=timestamp,
        nonce=nonce,
    )


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthenticationError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise AuthenticationError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def verify_signed_request(
    *,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    secret: bytes,
    expected_environment: str,
    used_nonces: set[tuple[str, str, str, str]],
    now: datetime | None = None,
    maximum_age: timedelta = timedelta(minutes=5),
) -> None:
    """Constant-time test/server verifier for the exact apply request binding."""
    missing = [name for name in HEADER_NAMES if not headers.get(name)]
    if missing:
        raise AuthenticationError("missing authentication header")
    if not hmac.compare_digest(method, HTTP_METHOD) or not hmac.compare_digest(
        path, REQUEST_PATH
    ):
        raise AuthenticationError("method or path mismatch")
    fixed = (
        (headers["X-Codestra-Signature-Version"], SIGNATURE_VERSION, "version"),
        (headers["X-Service-Identity"], IDENTITY, "identity"),
        (headers["X-Service-Audience"], AUDIENCE, "audience"),
        (headers["X-Codestra-Environment"], expected_environment, "environment"),
        (headers["X-Codestra-Scope"], APPLY_SCOPE, "scope"),
    )
    for supplied, expected, label in fixed:
        if not hmac.compare_digest(supplied, expected):
            raise AuthenticationError(f"{label} mismatch")
    body_hash = _sha256(body)
    if not hmac.compare_digest(headers["X-Codestra-Content-SHA256"], body_hash):
        raise AuthenticationError("body hash mismatch")
    request_time = _timestamp(headers["X-Codestra-Timestamp"])
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if abs(current - request_time) > maximum_age:
        raise AuthenticationError("timestamp expired")
    expected = hmac.new(
        secret,
        signing_material(
            headers["X-Codestra-Signature-Version"],
            method,
            path,
            headers["X-Codestra-Timestamp"],
            headers["X-Codestra-Nonce"],
            headers["X-Service-Identity"],
            headers["X-Service-Audience"],
            headers["X-Codestra-Environment"],
            headers["X-Codestra-Scope"],
            headers["Idempotency-Key"],
            body_hash,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(headers["X-Codestra-Signature"], expected):
        raise AuthenticationError("signature mismatch")
    nonce_key = (
        expected_environment,
        APPLY_SCOPE,
        path,
        headers["X-Codestra-Nonce"],
    )
    if nonce_key in used_nonces:
        raise ReplayError("nonce replay")
    used_nonces.add(nonce_key)


def _bounded_string(value: Any, label: str, maximum: int, prefix: str = "") -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ApplySchemaError(f"invalid {label}")
    if prefix and not value.startswith(prefix):
        raise ApplySchemaError(f"invalid {label}")
    return value


@lru_cache(maxsize=8)
def _attribute_schema(schema_key: str) -> dict[str, Any]:
    if schema_key not in {
        "transportation-logistics-lead-v1",
        "web-mobile-ai-lead-v1",
        "senior-citizen-products-lead-v1",
        "business-loan-lead-v1",
        "real-estate-lead-v1",
        "fundraising-lead-v1",
        "trading-ai-lead-v1",
        "farming-lead-v1",
    }:
        raise ApplySchemaError("unknown attributes_schema_key")
    path = (
        Path(__file__).resolve().parents[3]
        / "schemas"
        / "lead-automation"
        / f"{schema_key}.json"
    )
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApplySchemaError("registered attribute schema unavailable") from exc
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise ApplySchemaError("registered attribute schema is not fail-closed")
    return schema


def _validate_attributes(schema_key: str, attributes: Any) -> None:
    schema = _attribute_schema(schema_key)
    if not isinstance(attributes, dict) or len(attributes) > schema["maxProperties"]:
        raise ApplySchemaError("invalid attributes")
    properties = schema["properties"]
    if set(attributes) - set(properties):
        raise ApplySchemaError("attribute outside registered schema")
    for name, value in attributes.items():
        rule = properties[name]
        if "enum" in rule and value not in rule["enum"]:
            raise ApplySchemaError(f"invalid attribute {name}")
        if rule.get("type") == "boolean" and type(value) is not bool:
            raise ApplySchemaError(f"invalid attribute {name}")
        if rule.get("type") == "string" and (
            not isinstance(value, str) or not re.fullmatch(rule["pattern"], value)
        ):
            raise ApplySchemaError(f"invalid attribute {name}")


def validate_apply(payload: Mapping[str, Any]) -> None:
    keys = frozenset(payload)
    if (
        not REQUIRED_APPLY_FIELDS <= keys
        or keys - REQUIRED_APPLY_FIELDS - OPTIONAL_APPLY_FIELDS
    ):
        raise ApplySchemaError("apply fields do not match contract")
    if payload["contract_version"] != "1.1":
        raise ApplySchemaError("contract version mismatch")
    _bounded_string(payload["automation_event_id"], "automation_event_id", 68, "LAE-")
    idem = _bounded_string(payload["idempotency_key"], "idempotency_key", 64)
    if len(idem) != 64 or any(char not in "0123456789abcdefABCDEF" for char in idem):
        raise ApplySchemaError("invalid idempotency_key")
    if (
        payload["environment"] not in ENVIRONMENTS
        or payload["automation_action"] not in ACTIONS
    ):
        raise ApplySchemaError("invalid apply enum")
    for field, maximum in (
        ("company_key", 18),
        ("business_unit_key", 63),
        ("campaign_key", 64),
        ("policy_version", 32),
        ("attributes_schema_key", 64),
        ("result_code", 48),
    ):
        _bounded_string(payload[field], field, maximum)
    if not re.fullmatch(r"COMPANY-[1-9][0-9]{0,9}", payload["company_key"]):
        raise ApplySchemaError("invalid company_key")
    try:
        UUID(str(payload["correlation_id"]))
    except ValueError as exc:
        raise ApplySchemaError("invalid correlation_id") from exc
    _bounded_string(
        payload["workflow_execution_id"], "workflow_execution_id", 68, "N8N-"
    )
    for optional, prefix, maximum in (
        ("lead_uid", "LEAD-", 69),
        ("source_reference", "SRC-", 68),
    ):
        if optional in payload:
            _bounded_string(payload[optional], optional, maximum, prefix)
    _validate_attributes(payload["attributes_schema_key"], payload["attributes"])
    consent = payload["consent_snapshot"]
    expected_consent = {
        "consent_status",
        "consent_purpose",
        "consent_source",
        "consent_updated_at",
        "dnc_status",
        "dnc_updated_at",
        "jurisdiction",
        "source_system",
    }
    if not isinstance(consent, dict) or set(consent) != expected_consent:
        raise ApplySchemaError("invalid consent_snapshot")
    if consent["consent_status"] not in {
        "granted",
        "denied",
        "expired",
        "unknown",
    } or not isinstance(consent["dnc_status"], bool):
        raise ApplySchemaError("invalid consent_snapshot")


def build_apply_payload(
    *, event: Mapping[str, Any], result: Mapping[str, Any], automation_event_id: str
) -> dict[str, Any]:
    """Build and validate only the PII-free Odoo mutation contract."""
    payload = {
        "contract_version": "1.1",
        "automation_event_id": automation_event_id,
        "idempotency_key": event["idempotency_key"],
        "environment": event["environment"],
        "company_key": event["company_key"],
        "business_unit_key": event["business_unit_key"],
        "campaign_key": event["campaign_key"],
        "automation_action": event["automation_action"],
        "policy_version": event["policy_version"],
        "correlation_id": event["correlation_id"],
        "attributes_schema_key": event["attributes_schema_key"],
        "attributes": event["attributes"],
        "consent_snapshot": event["consent_snapshot"],
        "workflow_execution_id": result["workflow_execution_id"],
        "result_code": result["result_code"],
    }
    for optional in OPTIONAL_APPLY_FIELDS:
        if optional in event:
            payload[optional] = event[optional]
    validate_apply(payload)
    return payload


def validate_ack(ack: Mapping[str, Any], request: Mapping[str, Any]) -> None:
    keys = frozenset(ack)
    if (
        not REQUIRED_ACK_FIELDS <= keys
        or keys - REQUIRED_ACK_FIELDS - ACK_OPTIONAL_FIELDS
    ):
        raise AckValidationError("ack fields do not match contract")
    if ack["contract_version"] != "1.1" or ack["result"] not in ACK_RESULTS:
        raise AckValidationError("unknown acknowledgement contract or result")
    for field in (
        "automation_event_id",
        "automation_action",
        "company_key",
        "business_unit_key",
        "campaign_key",
        "policy_version",
    ):
        if ack[field] != request[field]:
            raise AckValidationError(f"ack {field} mismatch")
    expected_lead = request.get("lead_uid")
    if expected_lead is not None and ack["lead_uid"] != expected_lead:
        raise AckValidationError("ack lead_uid mismatch")
    try:
        _bounded_string(ack["lead_uid"], "lead_uid", 69, "LEAD-")
    except ApplySchemaError as exc:
        raise AckValidationError("invalid lead_uid") from exc
    if ack["odoo_record_id"] is not None and (
        not isinstance(ack["odoo_record_id"], int) or ack["odoo_record_id"] < 1
    ):
        raise AckValidationError("invalid odoo_record_id")
    if ack["result"] in {"APPLIED", "NO_CHANGE"} and ack["odoo_record_id"] is None:
        raise AckValidationError("successful ack requires odoo_record_id")
    for field in ("applied_fields", "unchanged_fields", "rejected_fields"):
        values = ack[field]
        if (
            not isinstance(values, list)
            or len(values) > 20
            or len(values) != len(set(values))
            or any(
                not isinstance(value, str) or not value or len(value) > 48
                for value in values
            )
        ):
            raise AckValidationError(f"invalid {field}")
    if not isinstance(ack["idempotent_replay"], bool):
        raise AckValidationError("invalid idempotent_replay")
    try:
        _timestamp(ack["updated_at"])
    except AuthenticationError as exc:
        raise AckValidationError("invalid updated_at") from exc
    if ack["result"] == "FAILED" and ack.get("result_code") is None:
        raise AckValidationError("FAILED requires result_code")


def classify_ack(ack: Mapping[str, Any]) -> str:
    result = ack["result"]
    if result in {"APPLIED", "NO_CHANGE"}:
        return "complete"
    if result == "FAILED" and ack.get("result_code") in RETRYABLE_RESULT_CODES:
        return "retry"
    return "permanent"


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    body: bytes


@dataclass(frozen=True)
class ApplyOutcome:
    request_body: bytes
    request_sha256: str
    ack: dict[str, Any]
    attempts: int
    replayed: bool


Transport = Callable[[str, str, bytes, Mapping[str, str], float], TransportResponse]


class OdooLeadApplyClient:
    """Source-only HTTP boundary; it has no database, bearer, or n8n capability."""

    def __init__(
        self,
        *,
        secret: bytes,
        transport: Transport,
        maximum_attempts: int = 3,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not secret or maximum_attempts < 1 or maximum_attempts > 5:
            raise ValueError("invalid Odoo apply client configuration")
        self._secret = secret
        self._transport = transport
        self._maximum_attempts = maximum_attempts
        self._timeout_seconds = timeout_seconds
        self._ledger: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        self.audit: list[dict[str, str]] = []

    def apply(self, payload: Mapping[str, Any]) -> ApplyOutcome:
        validate_apply(payload)
        body = canonical_body(payload)
        digest = _sha256(body)
        ledger_key = (payload["automation_event_id"], payload["idempotency_key"])
        previous = self._ledger.get(ledger_key)
        if previous:
            if not hmac.compare_digest(previous[0], digest):
                self.audit.append(
                    {
                        "automation_event_id": payload["automation_event_id"],
                        "result": "IDEMPOTENCY_CONFLICT",
                    }
                )
                raise IdempotencyConflict("conflicting Odoo apply replay")
            return ApplyOutcome(body, digest, previous[1], 0, True)
        for attempt in range(1, self._maximum_attempts + 1):
            headers = signed_headers_for_body(
                body, self._secret, payload["environment"], payload["idempotency_key"]
            )
            try:
                response = self._transport(
                    HTTP_METHOD, REQUEST_PATH, body, headers, self._timeout_seconds
                )
            except TimeoutError as exc:
                if attempt == self._maximum_attempts:
                    raise RetryExhausted(
                        "Odoo apply timeout retries exhausted"
                    ) from exc
                continue
            if response.status_code in RETRYABLE_HTTP_STATUS:
                if attempt == self._maximum_attempts:
                    raise RetryExhausted("Odoo apply HTTP retries exhausted")
                continue
            if response.status_code < 200 or response.status_code >= 300:
                raise PermanentApplyError("permanent Odoo apply HTTP response")
            try:
                ack = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PermanentApplyError("invalid acknowledgement JSON") from exc
            if not isinstance(ack, dict):
                raise PermanentApplyError("invalid acknowledgement schema")
            try:
                validate_ack(ack, payload)
            except (AckValidationError, AuthenticationError) as exc:
                raise PermanentApplyError(str(exc)) from exc
            classification = classify_ack(ack)
            if classification == "retry":
                if attempt == self._maximum_attempts:
                    raise RetryExhausted("retryable acknowledgement retries exhausted")
                continue
            if classification == "permanent":
                raise PermanentApplyError(
                    f"terminal Odoo acknowledgement: {ack['result']}"
                )
            self._ledger[ledger_key] = (digest, ack)
            return ApplyOutcome(body, digest, ack, attempt, False)
        raise RetryExhausted("Odoo apply retries exhausted")
