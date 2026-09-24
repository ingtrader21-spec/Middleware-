from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .domain import (
    Recording,
    RecordingConflict,
    RecordingNotFound,
    RecordingState,
    StateAudit,
)
from .odoo import OdooRecordingPort
from .retention import RetentionDecision, RetentionEngine
from .storage import PrivateObjectStorage

RETENTION_DAYS = {
    "synthetic_test": 7,
    "standard": 365,
    "high_compliance": 1825,
}


class RecordingService:
    def __init__(self, storage: PrivateObjectStorage, odoo: OdooRecordingPort) -> None:
        self.storage = storage
        self.odoo = odoo
        self.retention = RetentionEngine()
        self.recordings: dict[str, Recording] = {}
        self.by_idempotency: dict[tuple[str, str], str] = {}
        self.reservation_responses: dict[str, dict[str, Any]] = {}
        self.object_versions: dict[str, str] = {}
        self.failure_results: dict[tuple[str, str], dict[str, Any]] = {}
        self.audit: list[StateAudit] = []
        self.outbox: list[dict[str, Any]] = []
        self.playback_urls_persisted = 0

    def _transition(
        self, recording: Recording, state: RecordingState, reason: str
    ) -> None:
        previous = recording.state
        recording.state = state
        self.audit.append(
            StateAudit(
                recording.recording_uid,
                len(
                    [
                        a
                        for a in self.audit
                        if a.recording_uid == recording.recording_uid
                    ]
                )
                + 1,
                previous.value,
                state.value,
                reason,
            )
        )

    def reserve(self, payload: dict[str, Any]) -> dict[str, Any]:
        metadata = payload["recording"]
        key = (metadata["environment"], payload["idempotency_key"])
        if key in self.by_idempotency:
            existing = self.recordings[self.by_idempotency[key]]
            return dict(self.reservation_responses[existing.recording_uid])
        uid = f"REC-{uuid.uuid4().hex}"
        opaque = uuid.uuid4().hex
        recording = Recording(
            recording_uid=uid,
            environment=metadata["environment"],
            campaign_key=metadata["campaign_key"],
            call_uid=metadata["vicidial_call_id"],
            idempotency_key=payload["idempotency_key"],
            sha256=metadata["sha256"],
            file_size_bytes=metadata["file_size_bytes"],
            content_type={"mp3": "audio/mpeg", "wav": "audio/wav", "gsm": "audio/gsm"}[
                metadata["format"]
            ],
            opaque_object_identifier=opaque,
            retention_class=metadata["retention_class"],
            vicidial_recording_id=metadata["vicidial_recording_id"],
            asterisk_uniqueid=metadata["asterisk_uniqueid"],
            agent_key=metadata["agent_key"],
            started_at=metadata["started_at"],
            duration_seconds=metadata["duration_seconds"],
            format=metadata["format"],
            codec=metadata["codec"],
            channels=metadata["channels"],
            sample_rate_hz=metadata["sample_rate_hz"],
        )
        self.recordings[uid] = recording
        self.by_idempotency[key] = uid
        self._transition(recording, RecordingState.UPLOADING, "upload_authorized")
        url, expires = self.storage.reserve_upload(
            opaque, recording.content_type, recording.sha256, 300
        )
        response = self._reservation_response(recording, url, expires)
        self.reservation_responses[uid] = response
        return dict(response)

    @staticmethod
    def _reservation_response(
        recording: Recording, url: str, expires: datetime
    ) -> dict[str, Any]:
        return {
            "contract_version": "1.0",
            "recording_uid": recording.recording_uid,
            "upload_url": url,
            "upload_url_expires_at": expires.isoformat(),
            "required_checksum_header": "x-amz-checksum-sha256",
            "required_content_type": recording.content_type,
            "opaque_object_identifier": recording.opaque_object_identifier,
        }

    def get(self, recording_uid: str) -> Recording:
        try:
            return self.recordings[recording_uid]
        except KeyError as exc:
            raise RecordingNotFound(recording_uid) from exc

    async def complete(
        self, recording_uid: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        recording = self.get(recording_uid)
        completion_bindings = {
            "recording_uid": recording_uid,
            "idempotency_key": recording.idempotency_key,
            "environment": recording.environment,
            "campaign_key": recording.campaign_key,
            "sha256": recording.sha256,
            "file_size_bytes": recording.file_size_bytes,
            "format": recording.format,
            "duration_seconds": recording.duration_seconds,
        }
        mismatched_completion = sorted(
            key
            for key, expected in completion_bindings.items()
            if payload.get(key) != expected
        )
        if mismatched_completion:
            self._transition(
                recording,
                RecordingState.QUARANTINED,
                "completion:" + ",".join(mismatched_completion),
            )
            raise RecordingConflict("completion contract conflicts with reservation")
        if (
            recording.state == RecordingState.ODOO_LINKED
            and recording.object_version_id is not None
        ):
            return self._ack(recording, duplicate=True)
        if recording.state not in {
            RecordingState.UPLOADING,
            RecordingState.UPLOADED,
            RecordingState.SERVER_VERIFIED,
        }:
            raise RecordingConflict("completion conflicts with recording state")
        self._transition(recording, RecordingState.UPLOADED, "completion_received")
        try:
            head = self.storage.head(recording.opaque_object_identifier)
        except (KeyError, OSError):
            self._transition(recording, RecordingState.FAILED, "object_head_failed")
            raise RecordingConflict("object unavailable")
        version_id = head.version_id
        owner = self.object_versions.get(version_id)
        if owner is not None and owner != recording_uid:
            self._transition(recording, RecordingState.QUARANTINED, "version_conflict")
            raise RecordingConflict(
                "object version already belongs to another recording"
            )
        expected = {
            "sha256": recording.sha256,
            "file_size_bytes": recording.file_size_bytes,
            "content_type": recording.content_type,
            "version_id": version_id,
            "environment": recording.environment,
            "campaign_key": recording.campaign_key,
            "recording_uid": recording.recording_uid,
            "idempotency_key": recording.idempotency_key,
        }
        actual = {
            "sha256": head.checksum_sha256,
            "file_size_bytes": head.size_bytes,
            "content_type": head.content_type,
            "version_id": head.version_id,
            "environment": head.metadata.get("environment"),
            "campaign_key": head.metadata.get("campaign_key"),
            "recording_uid": head.metadata.get("recording_uid"),
            "idempotency_key": head.metadata.get("idempotency_key"),
        }
        mismatches = sorted(k for k in expected if expected[k] != actual[k])
        if mismatches:
            recording.failure_code = "OBJECT_METADATA_MISMATCH"
            self._transition(
                recording, RecordingState.QUARANTINED, ",".join(mismatches)
            )
            raise RecordingConflict("object verification mismatch")
        recording.object_version_id = version_id
        recording.verified_at = datetime.now(UTC)
        self.object_versions[version_id] = recording_uid
        self._transition(recording, RecordingState.SERVER_VERIFIED, "object_verified")
        retention_until = (
            None
            if recording.legal_hold or recording.retention_class == "legal_hold"
            else recording.verified_at
            + timedelta(days=RETENTION_DAYS[recording.retention_class])
        )
        metadata = {
            "contract_version": "1.0",
            "environment": recording.environment,
            "recording_uid": recording.recording_uid,
            "vicidial_recording_id": recording.vicidial_recording_id,
            "vicidial_call_id": recording.call_uid,
            "asterisk_uniqueid": recording.asterisk_uniqueid,
            "campaign_key": recording.campaign_key,
            "agent_key": recording.agent_key,
            "started_at": recording.started_at,
            "duration_seconds": recording.duration_seconds,
            "format": recording.format,
            "codec": recording.codec,
            "channels": recording.channels,
            "sample_rate_hz": recording.sample_rate_hz,
            "sha256": recording.sha256,
            "file_size_bytes": recording.file_size_bytes,
            "object_version_id": version_id,
            "storage_status": "verified",
            "retention_class": recording.retention_class,
            "retention_until": (
                retention_until.isoformat() if retention_until else None
            ),
            "legal_hold": recording.legal_hold,
        }
        try:
            acknowledgement = await self.odoo.upsert(
                metadata, recording.idempotency_key
            )
        except Exception:
            recording.failure_code = "ODOO_UPSERT_FAILED"
            raise
        required_acknowledgement = {
            "contract_version",
            "recording_uid",
            "odoo_record_id",
            "call_link_status",
            "lead_link_status",
            "campaign_link_status",
            "agent_link_status",
            "storage_status",
            "retention_class",
            "retention_until",
            "legal_hold",
            "updated_at",
        }
        if set(acknowledgement) != required_acknowledgement:
            raise RecordingConflict("canonical Odoo acknowledgement required")
        acknowledgement_bindings = {
            "contract_version": "1.0",
            "recording_uid": recording.recording_uid,
            "storage_status": metadata["storage_status"],
            "retention_class": recording.retention_class,
            "legal_hold": recording.legal_hold,
        }
        if any(
            acknowledgement.get(field) != expected
            for field, expected in acknowledgement_bindings.items()
        ):
            raise RecordingConflict("Odoo acknowledgement binding mismatch")
        acknowledged_retention = acknowledgement.get("retention_until")
        expected_retention = metadata["retention_until"]
        if (acknowledged_retention is None) != (expected_retention is None):
            raise RecordingConflict("Odoo acknowledgement retention mismatch")
        if acknowledged_retention is not None and datetime.fromisoformat(
            str(acknowledged_retention).replace("Z", "+00:00")
        ) != datetime.fromisoformat(str(expected_retention).replace("Z", "+00:00")):
            raise RecordingConflict("Odoo acknowledgement retention mismatch")
        recording.odoo_linked_at = datetime.now(UTC)
        self._transition(recording, RecordingState.ODOO_LINKED, "odoo_acknowledged")
        self.outbox.append(self._n8n_projection(recording))
        return self._ack(recording, duplicate=False)

    @staticmethod
    def _ack(recording: Recording, duplicate: bool) -> dict[str, Any]:
        return {
            "contract_version": "1.0",
            "recording_uid": recording.recording_uid,
            "state": recording.state.value,
            "checksum_verified": recording.verified_at is not None,
            "odoo_linked": recording.odoo_linked_at is not None,
            "duplicate": duplicate,
        }

    @staticmethod
    def _n8n_projection(recording: Recording) -> dict[str, Any]:
        return {
            "contract_version": "1.0",
            "event_id": uuid.uuid4().hex + uuid.uuid4().hex,
            "event_type": "vicidial.recording.verified.v1",
            "occurred_at": datetime.now(UTC).isoformat(),
            "environment": recording.environment,
            "recording_uid": recording.recording_uid,
            "call_uid": recording.call_uid,
            "campaign_key": recording.campaign_key,
            "duration_seconds": recording.duration_seconds,
            "sha256": recording.sha256,
            "object_version_id": recording.object_version_id,
            "retention_class": recording.retention_class,
        }

    def failure(
        self, recording_uid: str, code: str, idempotency_key: str
    ) -> dict[str, Any]:
        recording = self.get(recording_uid)
        key = (recording_uid, idempotency_key)
        if key in self.failure_results:
            return {**self.failure_results[key], "duplicate": True}
        if not idempotency_key or idempotency_key != recording.idempotency_key:
            raise RecordingConflict("failure idempotency binding mismatch")
        recording.failure_code = code
        self._transition(recording, RecordingState.FAILED, code)
        result = self._ack(recording, duplicate=False)
        self.failure_results[key] = result
        return result

    def playback_url(
        self,
        recording_uid: str,
        *,
        scope_authorized: bool,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        recording = self.get(recording_uid)
        if not scope_authorized:
            raise PermissionError("playback scope denied")
        if (
            recording.state != RecordingState.ODOO_LINKED
            or not recording.object_version_id
            or recording.legal_hold
        ):
            raise PermissionError("recording is not playable")
        ttl = min(ttl_seconds, 120)
        url = self.storage.presign_read(
            recording.opaque_object_identifier, recording.object_version_id, ttl
        )
        return {"playback_url": url, "expires_in": ttl}

    def automation_result(
        self, recording_uid: str, idempotency_key: str, result: dict[str, Any]
    ) -> dict[str, Any]:
        recording = self.get(recording_uid)
        forbidden = {
            "sha256",
            "checksum",
            "object_version_id",
            "object_key",
            "retention_class",
            "legal_hold",
        }
        if forbidden.intersection(result):
            raise RecordingConflict("automation result cannot mutate authority")
        duplicate = idempotency_key in recording.automation_results
        recording.automation_results.setdefault(idempotency_key, result)
        return {"accepted": True, "duplicate": duplicate}

    def retention_decision(
        self, recording_uid: str, now: datetime | None = None
    ) -> RetentionDecision:
        return self.retention.decide(self.get(recording_uid), now)
