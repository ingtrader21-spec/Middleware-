"""Canonical, provider-neutral test trace read model.

The records represented here remain owned by their source journals. This
module validates and orders redacted references; it does not persist a second
audit, event, identity, command, or reconciliation system.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any, Mapping, Sequence


TEST_BUSINESS_UNIT = "BU-400-COD"
TEST_CAMPAIGN = "CMP-400-COD"
TEST_AGENT_PUBLIC_ID = "400-AGT-90000001"
TEST_LEAD_PUBLIC_ID = "400-L-90000001"
TEST_CALLBACK_PUBLIC_ID = "400-CB-90000001"
TEST_EXTENSIONS = (7490, 7491, 7492, 7493, 7494)
PROHIBITED_EXTENSIONS = frozenset({6000, 6110, 6197, 6198})

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "sip_password",
        "turn_password",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "database_url",
        "connection_string",
        "phone_number",
        "email_address",
    }
)


class RecordEnvironment(StrEnum):
    TEST = "TEST"
    STAGING = "STAGING"


class TraceKind(StrEnum):
    ACTION = "ACTION"
    REACTION = "REACTION"
    RECONCILIATION = "RECONCILIATION"


class InvalidTestTrace(ValueError):
    pass


@dataclass(frozen=True)
class TraceRecord:
    test_run_id: str
    record_environment: RecordEnvironment
    organization_id: str
    business_unit_id: str
    campaign_id: str
    aggregate_type: str
    aggregate_id: str
    command_id: str
    command_type: str
    command_status: str
    idempotency_key: str
    correlation_id: str
    causation_id: str
    event_id: str
    trace_kind: TraceKind
    action_service: str
    action_name: str
    action_started_at: datetime
    action_completed_at: datetime
    policy_decision: str
    policy_version: str
    policy_hash: str
    target_system: str
    target_object_type: str
    target_object_id: str
    attempt_number: int
    response_classification: str
    response_status: str
    response_code: str
    response_summary: str
    response_hash: str
    response_received_at: datetime
    latency_ms: int
    reconciliation_status: str
    desired_version: int
    observed_version: int
    drift_classification: str
    reconciled_at: datetime | None
    created_by: str
    approved_by: str
    created_at: datetime
    updated_at: datetime
    evidence: Mapping[str, Any]

    def validate(self) -> None:
        required = {
            name: value for name, value in vars(self).items() if isinstance(value, str)
        }
        missing = sorted(name for name, value in required.items() if not value)
        if missing:
            raise InvalidTestTrace("missing fields: " + ",".join(missing))
        if self.record_environment not in {
            RecordEnvironment.TEST,
            RecordEnvironment.STAGING,
        }:
            raise InvalidTestTrace("production trace records are prohibited")
        if self.business_unit_id != TEST_BUSINESS_UNIT:
            raise InvalidTestTrace("test business unit mismatch")
        if self.campaign_id != TEST_CAMPAIGN:
            raise InvalidTestTrace("test campaign mismatch")
        if self.attempt_number < 1 or self.latency_ms < 0:
            raise InvalidTestTrace("attempt and latency must be bounded")
        if self.desired_version < 1 or self.observed_version < 0:
            raise InvalidTestTrace("invalid reconciliation version")
        if self.action_completed_at < self.action_started_at:
            raise InvalidTestTrace("action completion precedes start")
        if self.response_received_at < self.action_started_at:
            raise InvalidTestTrace("response precedes action")
        if self.updated_at < self.created_at:
            raise InvalidTestTrace("update precedes creation")
        for digest in (self.policy_hash, self.response_hash):
            if len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise InvalidTestTrace("trace hashes must be lowercase SHA-256")
        _validate_redacted(self.evidence)


@dataclass(frozen=True)
class TraceSummary:
    test_run_id: str
    action_count: int
    reaction_count: int
    reconciliation_count: int
    duplicate_action_count: int
    failed_action_count: int
    reconciliation_drift_count: int
    end_to_end_latency_ms: int


def select_test_extension(occupied: set[int], historically_used: set[int]) -> int:
    """Select the first controlled-test extension proven free everywhere."""
    conflicts = occupied | historically_used | PROHIBITED_EXTENSIONS
    for extension in TEST_EXTENSIONS:
        if extension not in conflicts:
            return extension
    raise InvalidTestTrace("no verified-free controlled-test extension")


def summarize_trace(records: Sequence[TraceRecord]) -> TraceSummary:
    if not records:
        raise InvalidTestTrace("trace is empty")
    for record in records:
        record.validate()
    ordered = sorted(records, key=lambda item: item.action_started_at)
    run_ids = {record.test_run_id for record in ordered}
    correlation_ids = {record.correlation_id for record in ordered}
    if len(run_ids) != 1 or len(correlation_ids) != 1:
        raise InvalidTestTrace("trace crosses run or correlation boundaries")
    actions = [record for record in ordered if record.trace_kind == TraceKind.ACTION]
    reactions = [
        record for record in ordered if record.trace_kind == TraceKind.REACTION
    ]
    reconciliations = [
        record for record in ordered if record.trace_kind == TraceKind.RECONCILIATION
    ]
    action_keys = {
        (record.command_id, record.action_service, record.action_name)
        for record in actions
    }
    duplicate_actions = len(actions) - len(action_keys)
    failed_actions = sum(record.response_status == "FAILED" for record in actions)
    drift = sum(record.drift_classification != "NONE" for record in reconciliations)
    start = min(record.action_started_at for record in ordered)
    finish = max(record.response_received_at for record in ordered)
    return TraceSummary(
        test_run_id=ordered[0].test_run_id,
        action_count=len(actions),
        reaction_count=len(reactions),
        reconciliation_count=len(reconciliations),
        duplicate_action_count=duplicate_actions,
        failed_action_count=failed_actions,
        reconciliation_drift_count=drift,
        end_to_end_latency_ms=int((finish - start).total_seconds() * 1000),
    )


def redacted_response_hash(summary: str) -> str:
    return sha256(summary.encode("utf-8")).hexdigest()


def _validate_redacted(value: Any, path: str = "evidence") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_KEYS:
                raise InvalidTestTrace(f"sensitive field prohibited: {path}.{key}")
            _validate_redacted(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_redacted(nested, f"{path}[{index}]")
