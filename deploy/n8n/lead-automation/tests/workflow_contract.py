"""Offline model of the inactive workflow contract; no network or live service use."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
CALLBACK_METHOD = "POST"
CALLBACK_PATH = "/api/v1/lead-automation/results"
SIGNATURE_VERSION = "HMAC-V2"
CALLBACK_SCOPE = "lead-automation.results.write"
IDENTITY = "codestra-n8n-lead-automation"
AUDIENCE = "codestra-middleware-lead-automation"
IDENTITY = "codestra-n8n-lead-automation"
AUDIENCE = "codestra-middleware-lead-automation"
BINDING_KEY = "n8n.leads.ingest"
MAXIMUM_ATTEMPTS = 5
RETRYABLE = {0, 429, 500, 502, 503, 504}
EVENT_ACTIONS = {
    "lead.creation.requested.v1": {"CREATE_LEAD"},
    "lead.update.requested.v1": {"UPDATE_ALLOWLISTED_FIELDS"},
    "lead.assignment.requested.v1": {
        "ASSIGN_AUTHORIZED_TEAM",
        "ASSIGN_AUTHORIZED_USER",
    },
    "lead.status_change.requested.v1": {"CHANGE_AUTHORIZED_STAGE"},
    "lead.callback_requested.v1": {"CREATE_INTERNAL_CALLBACK_ACTIVITY"},
}
PROHIBITED_KEY = re.compile(
    r"phone|email|customer.?name|street.?address|government|payment|credential|"
    r"provider.?token|hmac.?secret|recording|audio|filesystem|object.?key|"
    r"presigned|unrestricted.?notes",
    re.IGNORECASE,
)
EMAIL_VALUE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_VALUE = re.compile(r"^\+?[\d ().-]+$")


class ContractRejected(ValueError):
    pass


class ConflictingReplay(ContractRejected):
    pass


def _load(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text())


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _walk_prohibited(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if PROHIBITED_KEY.search(key):
                raise ContractRejected("prohibited field")
            _walk_prohibited(nested)
    elif isinstance(value, list):
        for nested in value:
            _walk_prohibited(nested)
    elif isinstance(value, str):
        digits = re.sub(r"\D", "", value)
        if EMAIL_VALUE.fullmatch(value) or (
            PHONE_VALUE.fullmatch(value) and 7 <= len(digits) <= 15
        ):
            raise ContractRejected("prohibited contact value")


def _validate_scalar(value: Any, rule: dict[str, Any]) -> None:
    expected = rule.get("type")
    if expected == "string" and not isinstance(value, str):
        raise ContractRejected("attribute type")
    if expected == "boolean" and not isinstance(value, bool):
        raise ContractRejected("attribute type")
    if "maxLength" in rule and len(value) > rule["maxLength"]:
        raise ContractRejected("attribute length")
    if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
        raise ContractRejected("attribute pattern")
    if "enum" in rule and value not in rule["enum"]:
        raise ContractRejected("attribute enum")


def validate_event(event: dict[str, Any]) -> None:
    schema = _load("lead-event-v1.json")
    _walk_prohibited(event)
    allowed = set(schema["properties"])
    if set(event) - allowed or any(key not in event for key in schema["required"]):
        raise ContractRejected("event envelope")
    if event["contract_version"] != "1.0" or event["environment"] != "staging":
        raise ContractRejected("version or environment")
    if event["event_type"] not in EVENT_ACTIONS:
        raise ContractRejected("event type")
    if event["automation_action"] not in EVENT_ACTIONS[event["event_type"]]:
        raise ContractRejected("action escalation")
    checks = (
        (r"^EVT-[A-Za-z0-9_-]{8,64}$", event["event_id"]),
        (r"^[a-z0-9][a-z0-9-]{1,62}$", event["business_unit_key"]),
        (r"^[A-Z0-9][A-Z0-9_-]{1,63}$", event["campaign_key"]),
        (r"^[A-Fa-f0-9]{64}$", event["idempotency_key"]),
        (r"^[A-Za-z0-9._-]{1,32}$", event["policy_version"]),
    )
    if any(not re.fullmatch(pattern, str(value)) for pattern, value in checks):
        raise ContractRejected("identifier")
    try:
        occurred = datetime.fromisoformat(event["occurred_at"])
    except (TypeError, ValueError) as exc:
        raise ContractRejected("timestamp") from exc
    if occurred.tzinfo is None or len(event["occurred_at"]) > 35:
        raise ContractRejected("timestamp")
    if event["event_type"] == "lead.creation.requested.v1":
        if "lead_uid" in event or not re.fullmatch(
            r"^SRC-[A-Za-z0-9_-]{8,64}$", event.get("source_reference", "")
        ):
            raise ContractRejected("creation identity")
    elif not re.fullmatch(
        r"^LEAD-[A-Za-z0-9_-]{8,64}$", event.get("lead_uid", "")
    ):
        raise ContractRejected("lead identity")
    schema_key = event["attributes_schema_key"]
    if schema_key not in schema["properties"]["attributes_schema_key"]["enum"]:
        raise ContractRejected("business-unit schema")
    attributes = event["attributes"]
    attribute_schema = _load(f"{schema_key}.json")
    if not isinstance(attributes, dict) or len(attributes) > attribute_schema["maxProperties"]:
        raise ContractRejected("attributes")
    if set(attributes) - set(attribute_schema["properties"]):
        raise ContractRejected("attribute allowlist")
    for key, value in attributes.items():
        _validate_scalar(value, attribute_schema["properties"][key])
    consent = event["consent_snapshot"]
    consent_schema = schema["properties"]["consent_snapshot"]
    if not isinstance(consent, dict) or set(consent) != set(consent_schema["required"]):
        raise ContractRejected("consent snapshot")
    if consent["consent_status"] not in consent_schema["properties"]["consent_status"]["enum"]:
        raise ContractRejected("consent status")
    if not isinstance(consent["dnc_status"], bool) or consent["source_system"] != "odoo":
        raise ContractRejected("DNC snapshot")


def callback_material(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    body_hash: str,
) -> bytes:
    values = (
        SIGNATURE_VERSION,
        method,
        path,
        timestamp,
        nonce,
        IDENTITY,
        AUDIENCE,
        "staging",
        CALLBACK_SCOPE,
        idempotency_key,
        body_hash,
    )
    if any(not value or "\n" in value or "\r" in value for value in values):
        raise ContractRejected("signing material")
    return "\n".join(values).encode("ascii")


def sign_result(
    body: bytes,
    *,
    secret: bytes,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    method: str = CALLBACK_METHOD,
    path: str = CALLBACK_PATH,
) -> dict[str, str]:
    body_hash = _sha(body)
    signature = hmac.new(
        secret,
        callback_material(method, path, timestamp, nonce, idempotency_key, body_hash),
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
        "X-Codestra-Environment": "staging",
        "X-Codestra-Scope": CALLBACK_SCOPE,
    }


class SyntheticMiddlewareStub:
    def __init__(self, secret: bytes) -> None:
        self.secret = secret
        self.nonces: set[str] = set()
        self.results: dict[str, str] = {}
        self.transitions = 0

    def accept(
        self,
        body: bytes,
        headers: dict[str, str],
        *,
        method: str = CALLBACK_METHOD,
        path: str = CALLBACK_PATH,
        query: str = "",
        now: datetime,
    ) -> dict[str, Any]:
        required = {
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
        }
        if set(headers) != required:
            raise ContractRejected("headers")
        if method != CALLBACK_METHOD or path != CALLBACK_PATH or query:
            raise ContractRejected("method or path")
        if headers["X-Service-Identity"] != IDENTITY or headers["X-Service-Audience"] != AUDIENCE:
            raise ContractRejected("identity")
        if headers["X-Codestra-Environment"] != "staging":
            raise ContractRejected("environment")
        if headers["X-Codestra-Signature-Version"] != SIGNATURE_VERSION:
            raise ContractRejected("version")
        if headers["X-Codestra-Scope"] != CALLBACK_SCOPE:
            raise ContractRejected("scope")
        body_hash = _sha(body)
        if not re.fullmatch(r"[0-9a-f]{64}", headers["X-Codestra-Content-SHA256"]):
            raise ContractRejected("body hash format")
        if not hmac.compare_digest(body_hash, headers["X-Codestra-Content-SHA256"]):
            raise ContractRejected("body hash")
        occurred = datetime.fromisoformat(headers["X-Codestra-Timestamp"])
        if occurred.tzinfo is None or abs(
            (now - occurred.astimezone(timezone.utc)).total_seconds()  # noqa: UP017 -- Python 3.10 CI
        ) > 300:
            raise ContractRejected("timestamp")
        material = callback_material(
            method,
            path,
            headers["X-Codestra-Timestamp"],
            headers["X-Codestra-Nonce"],
            headers["Idempotency-Key"],
            body_hash,
        )
        expected = hmac.new(self.secret, material, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, headers["X-Codestra-Signature"]):
            raise ContractRejected("signature")
        if headers["X-Codestra-Nonce"] in self.nonces:
            raise ContractRejected("nonce replay")
        self.nonces.add(headers["X-Codestra-Nonce"])
        result = json.loads(body)
        validate_result(result)
        digest = _sha(body)
        key = result["idempotency_key"]
        previous = self.results.get(key)
        if previous and previous != digest:
            raise ConflictingReplay("result replay")
        if not previous:
            self.results[key] = digest
            self.transitions += 1
        return {"accepted": True, "idempotent_replay": previous is not None}


def validate_result(result: dict[str, Any]) -> None:
    schema = _load("lead-automation-result-v1.json")
    _walk_prohibited(result)
    if set(result) != set(schema["required"]):
        raise ContractRejected("result envelope")
    for key in ("contract_version", "binding_key"):
        rule = schema["properties"][key]
        if result[key] != rule["const"]:
            raise ContractRejected(key)
    if result["environment"] != "staging":
        raise ContractRejected("environment")
    if result["automation_action"] not in schema["properties"]["automation_action"]["enum"]:
        raise ContractRejected("action")
    if result["result_status"] not in schema["properties"]["result_status"]["enum"]:
        raise ContractRejected("status")
    payload = result["result_payload"]
    allowed_payload = set(schema["properties"]["result_payload"]["properties"])
    if not isinstance(payload, dict) or set(payload) - allowed_payload:
        raise ContractRejected("result allowlist")


class WorkflowHarness:
    def __init__(self, secret: bytes = b"synthetic-n8n-callback-secret") -> None:
        self.secret = secret
        self.events: dict[str, tuple[str, dict[str, Any], bytes, dict[str, str]]] = {}
        self.callback_count = 0

    def process(self, event: dict[str, Any]) -> dict[str, Any]:
        validate_event(event)
        digest = _sha(_canonical(event).encode())
        key = f"{event['environment']}:{event['idempotency_key']}"
        if key in self.events:
            previous_digest, ack, _body, _headers = self.events[key]
            if previous_digest != digest:
                raise ConflictingReplay("event replay")
            return deepcopy(ack)
        execution = "N8N-" + _sha(f"{event['event_id']}:{event['idempotency_key']}".encode())[:32]
        result = {
            "contract_version": "1.0",
            "event_id": event["event_id"],
            "workflow_execution_id": execution,
            "binding_key": BINDING_KEY,
            "environment": event["environment"],
            "business_unit_key": event["business_unit_key"],
            "campaign_key": event["campaign_key"],
            "automation_action": event["automation_action"],
            "result_status": "SUCCEEDED",
            "result_code": "NO_CHANGE",
            "result_payload": {"transformation_version": "1.0"},
            "occurred_at": event["occurred_at"],
            "idempotency_key": event["idempotency_key"],
        }
        validate_result(result)
        body = json.dumps(result, separators=(",", ":")).encode()
        headers = sign_result(
            body,
            secret=self.secret,
            timestamp="2026-01-01T00:00:00+00:00",
            nonce="synthetic-" + digest[:24],
            idempotency_key=event["idempotency_key"],
        )
        ack = {
            "contract_version": "1.0",
            "event_id": event["event_id"],
            "accepted": True,
            "result_code": "ACCEPTED_FOR_RESULT_CALLBACK",
            "correlation_id": event["correlation_id"],
            "occurred_at": event["occurred_at"],
        }
        self.events[key] = (digest, ack, body, headers)
        self.callback_count += 1
        return deepcopy(ack)

    def callback(self, event: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
        key = f"{event['environment']}:{event['idempotency_key']}"
        return self.events[key][2], deepcopy(self.events[key][3])

    @staticmethod
    def attempts(statuses: list[int]) -> int:
        attempts = 0
        for status in statuses:
            attempts += 1
            if 200 <= status < 300:
                return attempts
            if status not in RETRYABLE or attempts >= MAXIMUM_ATTEMPTS:
                return attempts
        return attempts


def mutate(event: dict[str, Any], change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    candidate = deepcopy(event)
    change(candidate)
    return candidate
