from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Status(str, enum.Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    SUBMITTED = "SUBMITTED"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    DEFERRED = "DEFERRED"
    BOUNCED_SOFT = "BOUNCED_SOFT"
    BOUNCED_HARD = "BOUNCED_HARD"
    COMPLAINED = "COMPLAINED"
    SUPPRESSED = "SUPPRESSED"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


class Notification(Base):
    __tablename__ = "email_notification"
    notification_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(200), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    user_id: Mapped[str] = mapped_column(String(200), nullable=False)
    account_id: Mapped[str] = mapped_column(String(200), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(200), nullable=False)
    template_id: Mapped[str] = mapped_column(String(100), nullable=False)
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    recipient_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sender: Mapped[str] = mapped_column(String(320), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    locale: Mapped[str] = mapped_column(String(20), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[Status] = mapped_column(Enum(Status), nullable=False, default=Status.CREATED)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_class: Mapped[str | None] = mapped_column(String(80))
    provider_message_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_email_notification_tenant_idempotency"),
        Index("ix_email_notification_event", "tenant_id", "event_id"),
        Index("ix_email_notification_provider", "provider_message_id"),
        Index("ix_email_notification_recipient", "tenant_id", "recipient_hash"),
        Index("ix_email_notification_created", "created_at"),
        Index("ix_email_notification_status", "status"),
    )


class Outbox(Base):
    __tablename__ = "email_outbox"
    notification_id: Mapped[str] = mapped_column(ForeignKey("email_notification.notification_id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="QUEUED")
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    lease_owner: Mapped[str | None] = mapped_column(String(100))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_class: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (Index("ix_email_outbox_claim", "status", "available_at", "lease_expires_at"),)


class DeliveryEvent(Base):
    __tablename__ = "email_delivery_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider_event_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    provider_message_id: Mapped[str] = mapped_column(String(255), nullable=False)
    notification_id: Mapped[str] = mapped_column(ForeignKey("email_notification.notification_id"), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    normalized_status: Mapped[Status] = mapped_column(Enum(Status), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (Index("ix_email_delivery_provider_message", "provider_message_id"),)


class DeadLetter(Base):
    __tablename__ = "email_dead_letter"
    notification_id: Mapped[str] = mapped_column(ForeignKey("email_notification.notification_id"), primary_key=True)
    error_class: Mapped[str] = mapped_column(String(80), nullable=False)
    error_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Suppression(Base):
    __tablename__ = "email_suppression"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(200), nullable=False)
    recipient_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint("tenant_id", "recipient_hash", "reason", name="uq_email_suppression_boundary"),)


class TemplateVersion(Base):
    __tablename__ = "email_template_version"
    template_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    locale: Mapped[str] = mapped_column(String(20), primary_key=True)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    text_body: Mapped[str] = mapped_column(Text, nullable=False)
    html_body: Mapped[str] = mapped_column(Text, nullable=False)
    required_variables: Mapped[list] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class EmailTenant(Base):
    __tablename__ = "email_tenant"
    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    environment: Mapped[str] = mapped_column(String(30), nullable=False)
    service_scope: Mapped[str] = mapped_column(String(30), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class ServiceIdentityMapping(Base):
    __tablename__ = "email_service_identity_mapping"
    service_name: Mapped[str] = mapped_column(String(120), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("email_tenant.tenant_id"), nullable=False)
    environment: Mapped[str] = mapped_column(String(30), nullable=False)
    allowed_scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Department(Base):
    __tablename__ = "email_department"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("email_tenant.tenant_id"), nullable=False)
    address: Mapped[str] = mapped_column(String(320), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    __table_args__ = (
        UniqueConstraint("tenant_id", "address", name="uq_email_department_address"),
        UniqueConstraint("tenant_id", "slug", name="uq_email_department_slug"),
    )


class DepartmentMember(Base):
    __tablename__ = "email_department_member"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    department_id: Mapped[str] = mapped_column(ForeignKey("email_department.id"), nullable=False)
    employee_subject: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint("department_id", "employee_subject", name="uq_email_department_member"),)


class EmailCase(Base):
    __tablename__ = "email_case"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("email_tenant.tenant_id"), nullable=False)
    department_id: Mapped[str] = mapped_column(ForeignKey("email_department.id"), nullable=False)
    thread_key: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(998), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint("tenant_id", "thread_key", name="uq_email_case_thread"),)


class CaseMessage(Base):
    __tablename__ = "email_case_message"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("email_case.id"), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(255))
    message_id: Mapped[str] = mapped_column(String(998), nullable=False)
    in_reply_to: Mapped[str | None] = mapped_column(String(998))
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    sender: Mapped[str] = mapped_column(String(320), nullable=False)
    recipients: Mapped[list] = mapped_column(JSON, nullable=False)
    cc: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    subject: Mapped[str] = mapped_column(String(998), nullable=False)
    message_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    text_body: Mapped[str | None] = mapped_column(Text)
    html_body: Mapped[str | None] = mapped_column(Text)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class CaseEvent(Base):
    __tablename__ = "email_case_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("email_case.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_subject: Mapped[str | None] = mapped_column(String(200))
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class Attachment(Base):
    __tablename__ = "email_attachment"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id: Mapped[str] = mapped_column(ForeignKey("email_case_message.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str | None] = mapped_column(String(500))
    scan_status: Mapped[str] = mapped_column(String(30), nullable=False, default="PENDING")


class Archive(Base):
    __tablename__ = "email_archive"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("email_case.id"), nullable=False, unique=True)
    archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LegalHold(Base):
    __tablename__ = "email_legal_hold"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("email_case.id"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
