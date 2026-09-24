from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


class Recording(Base):
    __tablename__ = "recordings"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_uid: Mapped[str] = mapped_column(String(144), unique=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    campaign_key: Mapped[str] = mapped_column(String(128), nullable=False)
    call_uid: Mapped[str] = mapped_column(String(144), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    retention_class: Mapped[str] = mapped_column(String(32), nullable=False)
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "environment", "idempotency_key", name="uq_recording_environment_idempotency"
        ),
    )


class RecordingUploadReservation(Base):
    __tablename__ = "recording_upload_reservations"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(
        ForeignKey("recordings.id", ondelete="RESTRICT"), nullable=False
    )
    opaque_object_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RecordingObject(Base):
    __tablename__ = "recording_objects"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(
        ForeignKey("recordings.id", ondelete="RESTRICT"), nullable=False
    )
    object_version_id: Mapped[str | None] = mapped_column(String(255))
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        Index(
            "uq_recording_object_version_not_null",
            "object_version_id",
            unique=True,
            postgresql_where=text("object_version_id IS NOT NULL"),
        ),
    )


class RecordingDeliveryAttempt(Base):
    __tablename__ = "recording_delivery_attempts"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(ForeignKey("recordings.id"), nullable=False)
    destination: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    response_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RecordingRetentionPolicy(Base):
    __tablename__ = "recording_retention_policies"
    policy_class: Mapped[str] = mapped_column(String(32), primary_key=True)
    retention_days: Mapped[int | None] = mapped_column(Integer)
    version: Mapped[str] = mapped_column(String(32), nullable=False)


class RecordingRetentionDecision(Base):
    __tablename__ = "recording_retention_decisions"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(ForeignKey("recordings.id"), nullable=False)
    eligible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    eligible_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delete_executed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RecordingPlaybackAudit(Base):
    __tablename__ = "recording_playback_audit"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(ForeignKey("recordings.id"), nullable=False)
    service_identity: Mapped[str] = mapped_column(String(144), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RecordingOutbox(Base):
    __tablename__ = "recording_outbox"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(ForeignKey("recordings.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    binding_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RecordingStateAudit(Base):
    __tablename__ = "recording_state_audit"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    recording_id: Mapped[UUID] = mapped_column(ForeignKey("recordings.id"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(32))
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint("recording_id", "sequence", name="uq_recording_state_sequence"),
    )
