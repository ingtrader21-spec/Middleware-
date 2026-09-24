from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .domain import Recording, RecordingState

RETENTION_DAYS = {
    "synthetic_test": 7,
    "standard": 365,
    "high_compliance": 1825,
}


@dataclass(frozen=True)
class RetentionDecision:
    recording_uid: str
    eligible: bool
    reason: str
    eligible_at: datetime | None
    delete_executed: bool = False


class RetentionEngine:
    worker_enabled = True
    delete_enabled = False
    local_server_b_grace_days = 7

    def decide(
        self, recording: Recording, now: datetime | None = None
    ) -> RetentionDecision:
        current = now or datetime.now(UTC)
        blockers = (
            (recording.state != RecordingState.ODOO_LINKED, "ODOO_UNLINKED"),
            (recording.verified_at is None, "UPLOAD_UNVERIFIED"),
            (recording.odoo_linked_at is None, "ODOO_UNLINKED"),
            (recording.state == RecordingState.QUARANTINED, "QUARANTINED"),
            (recording.legal_hold, "LEGAL_HOLD"),
            (recording.retention_class not in RETENTION_DAYS, "POLICY_UNRESOLVED"),
        )
        for blocked, reason in blockers:
            if blocked:
                return RetentionDecision(recording.recording_uid, False, reason, None)
        assert recording.verified_at and recording.odoo_linked_at
        retention_expiry = recording.verified_at + timedelta(
            days=RETENTION_DAYS[recording.retention_class]
        )
        grace_expiry = recording.odoo_linked_at + timedelta(
            days=self.local_server_b_grace_days
        )
        eligible_at = max(retention_expiry, grace_expiry)
        if current < eligible_at:
            return RetentionDecision(
                recording.recording_uid, False, "NOT_BEFORE_EXPIRY", eligible_at
            )
        return RetentionDecision(
            recording.recording_uid, True, "ELIGIBLE_DELETE_DISABLED", eligible_at
        )
