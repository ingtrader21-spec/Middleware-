from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.recording.domain import ObjectHead, RecordingConflict, RecordingState
from app.recording.odoo import AcknowledgingOdooClient
from app.recording.security import (
    AuthenticationError,
    ExporterIdentity,
    MTLSAuthorizer,
    ReplayGuard,
)
from app.recording.service import RecordingService
from app.recording.storage import MemoryObjectStorage

SHA = "a" * 64


def reservation(**updates):
    recording = {
        "contract_version": "1.0",
        "vicidial_recording_id": "123",
        "vicidial_call_id": "call-fixture",
        "asterisk_uniqueid": "asterisk-fixture",
        "campaign_key": "SYNTHETIC",
        "agent_key": "agent-fixture",
        "started_at": "2026-07-31T00:00:00Z",
        "duration_seconds": 1.5,
        "format": "mp3",
        "codec": "mp3",
        "channels": 1,
        "sample_rate_hz": 8000,
        "file_size_bytes": 123,
        "sha256": SHA,
        "environment": "staging",
        "retention_class": "synthetic_test",
    }
    recording.update(updates)
    return {
        "contract_version": "1.0",
        "idempotency_key": "a" * 64,
        "recording": recording,
    }


def completion(service, response, **updates):
    recording = service.get(response["recording_uid"])
    payload = {
        "contract_version": "1.0",
        "recording_uid": recording.recording_uid,
        "idempotency_key": recording.idempotency_key,
        "environment": recording.environment,
        "campaign_key": recording.campaign_key,
        "sha256": recording.sha256,
        "file_size_bytes": recording.file_size_bytes,
        "format": recording.format,
        "duration_seconds": recording.duration_seconds,
    }
    payload.update(updates)
    return payload


def setup_object(service, response, **metadata_updates):
    recording = service.get(response["recording_uid"])
    metadata = {
        "environment": recording.environment,
        "campaign_key": recording.campaign_key,
        "recording_uid": recording.recording_uid,
        "idempotency_key": recording.idempotency_key,
    }
    metadata.update(metadata_updates)
    service.storage.objects[(recording.opaque_object_identifier, "v1")] = ObjectHead(
        123, "audio/mpeg", SHA, "v1", metadata
    )


def test_mtls_role_audience_environment_and_replay_gate():
    auth = MTLSAuthorizer({"spiffe://codestra/server-b": "staging"})
    auth.authorize(
        ExporterIdentity(
            "spiffe://codestra/server-b",
            "staging",
            "recording-exporter",
            "codestra-recording-api",
            datetime.now(UTC) + timedelta(days=1),
        )
    )
    with pytest.raises(AuthenticationError):
        auth.authorize(
            ExporterIdentity(
                "spiffe://codestra/server-b",
                "production",
                "recording-exporter",
                "codestra-recording-api",
                datetime.now(UTC) + timedelta(days=1),
            )
        )
    replay = ReplayGuard()
    now = 1_800_000_000
    replay.consume("unique-nonce", now, now)
    with pytest.raises(AuthenticationError):
        replay.consume("unique-nonce", now, now)


@pytest.mark.asyncio
async def test_reservation_verification_odoo_ack_duplicate_and_event():
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    first = service.reserve(reservation())
    duplicate = service.reserve(reservation())
    assert duplicate["recording_uid"] == first["recording_uid"]
    assert duplicate == first
    assert first["upload_url_expires_at"]
    assert "credentials" not in first and "object_key" not in first
    setup_object(service, first)
    ack = await service.complete(first["recording_uid"], completion(service, first))
    assert ack["checksum_verified"] and ack["odoo_linked"]
    assert service.get(first["recording_uid"]).state == RecordingState.ODOO_LINKED
    assert service.outbox[0]["event_type"] == "vicidial.recording.verified.v1"
    assert "recording" not in service.outbox[0]
    assert set(service.outbox[0]) == {
        "contract_version",
        "event_id",
        "event_type",
        "occurred_at",
        "environment",
        "recording_uid",
        "call_uid",
        "campaign_key",
        "duration_seconds",
        "sha256",
        "object_version_id",
        "retention_class",
    }
    replay = await service.complete(first["recording_uid"], completion(service, first))
    assert replay["duplicate"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metadata_update",
    [
        {"environment": "production"},
        {"campaign_key": "WRONG"},
        {"recording_uid": "REC-wrong"},
        {"idempotency_key": "wrong-idempotency-key"},
    ],
)
async def test_metadata_mismatch_quarantines(metadata_update):
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    response = service.reserve(reservation())
    setup_object(service, response, **metadata_update)
    with pytest.raises(RecordingConflict):
        await service.complete(response["recording_uid"], completion(service, response))
    assert service.get(response["recording_uid"]).state == RecordingState.QUARANTINED


@pytest.mark.asyncio
async def test_size_checksum_content_type_and_version_are_verified():
    for field, value in (
        ("size_bytes", 124),
        ("checksum_sha256", "b" * 64),
        ("content_type", "audio/wav"),
    ):
        service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
        response = service.reserve(reservation())
        recording = service.get(response["recording_uid"])
        head = ObjectHead(
            123,
            "audio/mpeg",
            SHA,
            "v1",
            {
                "environment": "staging",
                "campaign_key": "SYNTHETIC",
                "recording_uid": recording.recording_uid,
                "idempotency_key": recording.idempotency_key,
            },
        )
        object.__setattr__(head, field, value)
        service.storage.objects[(recording.opaque_object_identifier, "v1")] = head
        with pytest.raises(RecordingConflict):
            await service.complete(
                recording.recording_uid, completion(service, response)
            )


@pytest.mark.asyncio
async def test_object_version_is_unique_across_recordings():
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    first = service.reserve(reservation())
    setup_object(service, first)
    await service.complete(first["recording_uid"], completion(service, first))
    second_payload = reservation(vicidial_recording_id="124", vicidial_call_id="call-2")
    second_payload["idempotency_key"] = "b" * 64
    second = service.reserve(second_payload)
    setup_object(service, second)
    with pytest.raises(RecordingConflict):
        await service.complete(second["recording_uid"], completion(service, second))
    assert service.get(second["recording_uid"]).state == RecordingState.QUARANTINED


class FailingOdoo:
    async def upsert(self, metadata, idempotency_key):
        raise RuntimeError("temporary Odoo failure")


class IncompleteAcknowledgementOdoo:
    async def upsert(self, metadata, idempotency_key):
        return {
            "contract_version": "1.0",
            "recording_uid": metadata["recording_uid"],
        }


@pytest.mark.asyncio
async def test_odoo_ack_required_and_retry_state_never_links_early():
    service = RecordingService(MemoryObjectStorage(), FailingOdoo())
    response = service.reserve(reservation())
    setup_object(service, response)
    with pytest.raises(RuntimeError):
        await service.complete(response["recording_uid"], completion(service, response))
    recording = service.get(response["recording_uid"])
    assert recording.state == RecordingState.SERVER_VERIFIED
    assert recording.odoo_linked_at is None
    assert service.outbox == []


@pytest.mark.asyncio
async def test_incomplete_canonical_ack_never_links():
    service = RecordingService(MemoryObjectStorage(), IncompleteAcknowledgementOdoo())
    response = service.reserve(reservation())
    setup_object(service, response)
    with pytest.raises(RecordingConflict, match="canonical Odoo acknowledgement"):
        await service.complete(response["recording_uid"], completion(service, response))
    recording = service.get(response["recording_uid"])
    assert recording.state == RecordingState.SERVER_VERIFIED
    assert recording.odoo_linked_at is None
    assert service.outbox == []


class CapturingOdoo(AcknowledgingOdooClient):
    def __init__(self):
        self.metadata = None

    async def upsert(self, metadata, idempotency_key):
        self.metadata = metadata
        return await super().upsert(metadata, idempotency_key)


@pytest.mark.asyncio
async def test_odoo_upsert_payload_is_complete():
    odoo = CapturingOdoo()
    service = RecordingService(MemoryObjectStorage(), odoo)
    response = service.reserve(reservation())
    setup_object(service, response)
    await service.complete(response["recording_uid"], completion(service, response))
    assert set(odoo.metadata) == {
        "contract_version",
        "environment",
        "recording_uid",
        "vicidial_recording_id",
        "vicidial_call_id",
        "asterisk_uniqueid",
        "campaign_key",
        "agent_key",
        "started_at",
        "duration_seconds",
        "format",
        "codec",
        "channels",
        "sample_rate_hz",
        "file_size_bytes",
        "sha256",
        "object_version_id",
        "storage_status",
        "retention_class",
        "retention_until",
        "legal_hold",
    }


@pytest.mark.asyncio
async def test_playback_scope_ttl_nonpersistence_and_retention_gates():
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    response = service.reserve(reservation())
    setup_object(service, response)
    await service.complete(response["recording_uid"], completion(service, response))
    with pytest.raises(PermissionError):
        service.playback_url(
            response["recording_uid"], scope_authorized=False, ttl_seconds=120
        )
    body = service.playback_url(
        response["recording_uid"], scope_authorized=True, ttl_seconds=120
    )
    assert body["expires_in"] <= 120
    assert service.playback_urls_persisted == 0
    recording = service.get(response["recording_uid"])
    before = service.retention_decision(
        response["recording_uid"], recording.verified_at + timedelta(days=6)
    )
    assert not before.eligible
    after = service.retention_decision(
        response["recording_uid"], recording.verified_at + timedelta(days=8)
    )
    assert after.eligible and not after.delete_executed
    recording.legal_hold = True
    assert not service.retention_decision(
        response["recording_uid"], datetime.now(UTC) + timedelta(days=100)
    ).eligible


def test_automation_result_idempotent_and_authority_protected():
    service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
    response = service.reserve(reservation())
    result = {"transcription_status": "submitted"}
    first = service.automation_result(
        response["recording_uid"], "automation-result-key", result
    )
    second = service.automation_result(
        response["recording_uid"], "automation-result-key", result
    )
    assert first["duplicate"] is False and second["duplicate"] is True
    with pytest.raises(RecordingConflict):
        service.automation_result(
            response["recording_uid"], "different-result-key", {"sha256": "x"}
        )
