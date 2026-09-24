"""Strict, versioned, data-minimised VICIdial event registry."""

import hashlib
import json
from datetime import datetime
from typing import Literal, cast, TypedDict
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CallIdentity(StrictModel):
    call_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


class CallEnded(CallIdentity):
    ended_at: datetime
    duration_seconds: int = Field(ge=0, le=86400)
    direction: Literal["inbound", "outbound"]


class LifecyclePayload(StrictModel):
    lifecycle_status: Literal["STARTED", "CONNECTED", "ENDED"]
    disposition: str | None = Field(default=None, max_length=64)
    hangup_cause: str | None = Field(default=None, max_length=64)


class DispositionApplied(CallIdentity):
    disposition_code: str = Field(min_length=1, max_length=32, pattern=r"^[A-Z0-9_-]+$")
    applied_at: datetime


class Callback(CallIdentity):
    callback_id: str = Field(min_length=1, max_length=128)
    scheduled_at: datetime


class CallbackCompleted(CallIdentity):
    callback_id: str = Field(min_length=1, max_length=128)
    completed_at: datetime
    outcome: str = Field(min_length=1, max_length=32)


class AgentState(StrictModel):
    agent_id: str = Field(min_length=1, max_length=64)
    state: Literal["available", "busy", "pause", "after_call_work", "offline"]
    changed_at: datetime


class RecordingReady(CallIdentity):
    recording_id: str = Field(min_length=1, max_length=128)
    ready_at: datetime


class QueueAbandoned(CallIdentity):
    queue_id: str = Field(min_length=1, max_length=64)
    abandoned_at: datetime
    wait_seconds: int = Field(ge=0, le=86400)


class TransferCompleted(CallIdentity):
    transfer_id: str = Field(min_length=1, max_length=128)
    completed_at: datetime
    target_type: Literal["agent", "queue", "external"]


class HopperState(StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    remaining: int = Field(ge=0)
    observed_at: datetime


class CarrierState(StrictModel):
    carrier_id: str = Field(min_length=1, max_length=64)
    observed_at: datetime
    reason_code: str = Field(min_length=1, max_length=64)


class PredictiveThrottled(StrictModel):
    campaign_id: str = Field(min_length=1, max_length=64)
    observed_at: datetime
    reason_code: str = Field(min_length=1, max_length=64)


PAYLOADS: dict[str, type[StrictModel]] = {
    "vicidial.call.started": LifecyclePayload,
    "vicidial.call.connected": LifecyclePayload,
    "vicidial.call.ended": CallEnded,
    "vicidial.disposition.applied": DispositionApplied,
    "vicidial.callback.created": Callback,
    "vicidial.callback.updated": Callback,
    "vicidial.callback.completed": CallbackCompleted,
    "vicidial.agent.state.changed": AgentState,
    "vicidial.recording.ready": RecordingReady,
    "vicidial.queue.abandoned": QueueAbandoned,
    "vicidial.transfer.completed": TransferCompleted,
    "vicidial.hopper.low": HopperState,
    "vicidial.hopper.empty": HopperState,
    "vicidial.carrier.degraded": CarrierState,
    "vicidial.carrier.failover": CarrierState,
    "vicidial.predictive.throttled": PredictiveThrottled,
}


class Envelope(StrictModel):
    schema_version: Literal["1.0"]
    event_id: UUID
    event_type: str = Field(min_length=1, max_length=100)
    occurred_at: datetime
    correlation_id: str = Field(min_length=1, max_length=128)
    client_instance: str = Field(min_length=1, max_length=64)
    business_unit: (
        Literal["MOY", "COD", "SCP", "MBL", "RLP", "FTP", "TRX", "CAL"] | None
    ) = None
    source_system: str | None = Field(default=None, max_length=64)
    producer_instance_id: str | None = Field(default=None, max_length=128)
    producer_boot_id: str | None = Field(default=None, max_length=128)
    payload_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    asterisk_unique_id: str | None = Field(default=None, max_length=119)
    asterisk_linked_id: str | None = Field(default=None, max_length=119)
    channel: str | None = Field(default=None, max_length=255)
    source_extension: str | None = Field(default=None, max_length=32)
    destination: str | None = Field(default=None, max_length=64)
    dialplan_context: str | None = Field(default=None, max_length=128)
    payload: dict


class EventDefinition(TypedDict):
    version: str
    model: type[StrictModel]
    deprecated: bool
    production_enabled: bool


REGISTRY: dict[str, EventDefinition] = {
    name: {
        "version": "1.0",
        "model": model,
        "deprecated": False,
        "production_enabled": name == "vicidial.call.ended",
    }
    for name, model in PAYLOADS.items()
}


def parse_event(raw: bytes, enabled: frozenset[str]) -> tuple[Envelope, StrictModel]:
    envelope = Envelope.model_validate_json(raw)
    definition = REGISTRY.get(envelope.event_type)
    if definition is None or envelope.event_type not in enabled:
        raise ValueError("event type is not enabled")
    lifecycle_event = envelope.event_type in {
        "vicidial.call.started",
        "vicidial.call.connected",
    } or (
        envelope.event_type == "vicidial.call.ended"
        and "lifecycle_status" in envelope.payload
    )
    if lifecycle_event:
        payload: StrictModel = LifecyclePayload.model_validate(envelope.payload)
    else:
        payload_model = cast(type[StrictModel], definition["model"])
        payload = payload_model.model_validate(envelope.payload)
    if lifecycle_event:
        required = (
            envelope.source_system,
            envelope.producer_instance_id,
            envelope.producer_boot_id,
            envelope.payload_sha256,
            envelope.asterisk_unique_id,
            envelope.channel,
            envelope.source_extension,
            envelope.destination,
            envelope.dialplan_context,
        )
        if any(value is None for value in required):
            raise ValueError("lifecycle envelope fields are required")
        canonical = json.dumps(
            envelope.payload, sort_keys=True, separators=(",", ":")
        ).encode()
        if hashlib.sha256(canonical).hexdigest() != envelope.payload_sha256:
            raise ValueError("payload integrity hash mismatch")
        expected_status = {
            "vicidial.call.started": "STARTED",
            "vicidial.call.connected": "CONNECTED",
            "vicidial.call.ended": "ENDED",
        }[envelope.event_type]
        if not isinstance(payload, LifecyclePayload):
            raise ValueError("lifecycle payload model mismatch")
        if payload.lifecycle_status != expected_status:
            raise ValueError("event type and lifecycle status mismatch")
    return envelope, payload
