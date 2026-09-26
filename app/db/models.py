from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import (
    INT4RANGE,
    JSONB,
    ExcludeConstraint,
)
from sqlalchemy.dialects.postgresql import (
    UUID as PGUUID,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TelephonyCommandJournal(Base):
    __tablename__ = "telephony_command_journal"
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    command_public_id: Mapped[str] = mapped_column(
        String(144), nullable=False, unique=True, default=lambda: f"CMD-{uuid4().hex}"
    )
    command_type: Mapped[str] = mapped_column(String(96), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_public_id: Mapped[str] = mapped_column(String(144), nullable=False)
    aggregate_version: Mapped[int] = mapped_column(Integer, nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    business_unit_public_id: Mapped[str] = mapped_column(String(144), nullable=False)
    campaign_public_id: Mapped[str] = mapped_column(String(144), nullable=False)
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    causation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_decision_id: Mapped[str] = mapped_column(String(144), nullable=False)
    policy_decision_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    __table_args__ = (
        CheckConstraint("aggregate_version >= 1", name="ck_telephony_command_version"),
        CheckConstraint(
            "environment IN ('staging','test','production')",
            name="ck_telephony_command_environment",
        ),
        UniqueConstraint(
            "environment",
            "aggregate_type",
            "aggregate_public_id",
            "aggregate_version",
            name="uq_telephony_command_aggregate_version",
        ),
        Index(
            "ix_telephony_command_aggregate",
            "aggregate_type",
            "aggregate_public_id",
            "aggregate_version",
        ),
        Index("ix_telephony_command_correlation", "correlation_id"),
    )


class TelephonyOperationJournal(Base):
    __tablename__ = "telephony_operation_journal"
    operation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    operation_public_id: Mapped[str] = mapped_column(
        String(144), nullable=False, unique=True, default=lambda: f"OPR-{uuid4().hex}"
    )
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_command_journal.command_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter_service_key: Mapped[str] = mapped_column(
        String(144), nullable=False, default="telephony-adapter"
    )
    adapter_operation_id: Mapped[str] = mapped_column(
        String(144), nullable=False, default=""
    )
    target_system: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    target_resource_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=""
    )
    target_public_id: Mapped[str] = mapped_column(
        String(144), nullable=False, default=""
    )
    desired_state_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, default=lambda: uuid4().hex
    )
    transition_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoint_key: Mapped[str] = mapped_column(String(96), nullable=False)
    readback_endpoint_key: Mapped[str] = mapped_column(String(96), nullable=False)
    target_configuration_checksum: Mapped[str] = mapped_column(
        String(71), nullable=False
    )
    target_attested: Mapped[bool] = mapped_column(Boolean, nullable=False)
    desired_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_hash: Mapped[str | None] = mapped_column(String(64))
    readback_matches: Mapped[bool | None] = mapped_column(Boolean)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    response_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint(
            "(readback_matches IS NOT TRUE) OR (actual_hash IS NOT NULL)",
            name="ck_telephony_operation_readback_hash",
        ),
        Index("ix_telephony_operation_correlation", "correlation_id"),
    )


class TelephonyOperationTransition(Base):
    __tablename__ = "telephony_operation_transition"
    transition_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    operation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_operation_journal.operation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_command_journal.command_id", ondelete="RESTRICT"),
        nullable=False,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    transition_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    binding_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "operation_id", "sequence", name="uq_telephony_transition_sequence"
        ),
        UniqueConstraint(
            "operation_id",
            "transition_hash",
            name="uq_telephony_transition_hash",
        ),
    )


class TelephonyTerminalResult(Base):
    __tablename__ = "telephony_terminal_result"
    result_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    result_public_id: Mapped[str] = mapped_column(
        String(144), nullable=False, unique=True, default=lambda: f"RES-{uuid4().hex}"
    )
    operation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_operation_journal.operation_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_command_journal.command_id", ondelete="RESTRICT"),
        nullable=False,
    )
    result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    application_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    readback_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_system: Mapped[str] = mapped_column(String(32), nullable=False)
    target_resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_public_id: Mapped[str] = mapped_column(String(144), nullable=False)
    requested_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    applied_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    application_status: Mapped[str] = mapped_column(String(32), nullable=False)
    readback_status: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter_service_key: Mapped[str] = mapped_column(String(144), nullable=False)
    adapter_configuration_checksum: Mapped[str] = mapped_column(
        String(71), nullable=False
    )
    safe_summary: Mapped[str] = mapped_column(String(512), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    readback_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    odoo_callback_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reconciliation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    immutable_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "result_hash", "operation_id", name="uq_telephony_result_binding"
        ),
        Index("ix_telephony_result_correlation", "correlation_id"),
    )


class TelephonyReconciliationRun(Base):
    __tablename__ = "telephony_reconciliation_run"
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    run_public_id: Mapped[str] = mapped_column(
        String(144), nullable=False, unique=True, default=lambda: f"REC-{uuid4().hex}"
    )
    command_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_command_journal.command_id", ondelete="RESTRICT"),
    )
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_public_id: Mapped[str] = mapped_column(String(144), nullable=False)
    target_system: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        Index("ix_telephony_reconciliation_correlation", "correlation_id"),
    )


class IntegrationEvent(Base):
    __tablename__ = "integration_event"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    original_event_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    entity_key: Mapped[str | None] = mapped_column(String(256))
    source_system: Mapped[str] = mapped_column(
        String(50), nullable=False, default="vicidial"
    )
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (Index("ix_integration_event_payload_hash", "payload_hash"),)


class IntegrationDelivery(Base):
    __tablename__ = "integration_delivery"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("integration_event.id", ondelete="CASCADE"),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="disabled")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    __table_args__ = (
        UniqueConstraint("event_id", "target", name="uq_delivery_event_target"),
    )


class BroadEventDelivery(Base):
    __tablename__ = "broad_event_delivery"
    delivery_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("integration_event.id"), nullable=False
    )
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    target_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    target_environment: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="RESERVED")
    reserved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response_received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_class: Mapped[str | None] = mapped_column(String(64))
    response_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    __table_args__ = (
        UniqueConstraint(
            "event_id",
            "workflow_id",
            "workflow_version",
            "idempotency_key",
            name="uq_broad_event_delivery_scope",
        ),
    )


class N8nTargetAttestation(Base):
    __tablename__ = "n8n_target_attestation"
    attestation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    target_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    target_environment: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_host: Mapped[str] = mapped_column(String(255), nullable=False)
    image_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    workflow_package_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_nonce: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class N8nExecutionRegistration(Base):
    __tablename__ = "n8n_execution_registration"
    execution_registration_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    registration_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, unique=True
    )
    delivery_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("broad_event_delivery.delivery_id"),
        unique=True,
    )
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(128), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="REGISTERED"
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    response_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class N8nExecutionTransition(Base):
    __tablename__ = "n8n_execution_transition"
    transition_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    registration_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("n8n_execution_registration.registration_id"),
        nullable=False,
    )
    from_status: Mapped[str] = mapped_column(String(24), nullable=False)
    to_status: Mapped[str] = mapped_column(String(24), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "registration_id",
            "to_status",
            name="uq_n8n_transition_registration_status",
        ),
    )


class N8nAcknowledgement(Base):
    __tablename__ = "n8n_acknowledgement"
    acknowledgement_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True
    )
    registration_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("n8n_execution_registration.registration_id"),
        nullable=False,
    )
    delivery_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("broad_event_delivery.delivery_id"),
        unique=True,
    )
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(128), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    execution_status: Mapped[str] = mapped_column(String(24), nullable=False)
    result_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class N8nWorkflowRegistry(Base):
    __tablename__ = "n8n_workflow_registry"
    registry_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    workflow_code: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(32), nullable=False)
    n8n_workflow_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    tenant_scope: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=600)
    retry_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    result_contract: Mapped[str] = mapped_column(String(64), nullable=False)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    webhook_path: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "workflow_code", "workflow_version", name="uq_n8n_registry_code_version"
        ),
        UniqueConstraint("n8n_workflow_id", name="uq_n8n_registry_workflow_id"),
    )


class N8nRuntimeExecution(Base):
    __tablename__ = "n8n_runtime_execution"
    execution_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_code: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(32), nullable=False)
    n8n_execution_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    causation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    failure_class: Mapped[str | None] = mapped_column(String(64))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "event_type",
            "source_event_id",
            "workflow_version",
            "idempotency_key_hash",
            name="uq_n8n_runtime_idempotency",
        ),
        Index("ix_n8n_runtime_claim", "status", "next_attempt_at", "created_at"),
        Index("ix_n8n_runtime_tenant_correlation", "tenant_id", "correlation_id"),
    )


class N8nRuntimeResult(Base):
    __tablename__ = "n8n_runtime_result"
    result_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    execution_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("n8n_runtime_execution.execution_id", ondelete="RESTRICT"),
        nullable=False,
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    workflow_code: Mapped[str] = mapped_column(String(128), nullable=False)
    result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "execution_id", "result_hash", name="uq_n8n_runtime_result_hash"
        ),
    )


class N8nRuntimeNonce(Base):
    __tablename__ = "n8n_runtime_nonce"
    identity: Mapped[str] = mapped_column(String(128), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class OdooResultDelivery(Base):
    __tablename__ = "odoo_result_delivery"
    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(acknowledgement_id, runtime_result_id, integration_event_id) = 1",
            name="ck_odoo_result_delivery_one_source",
        ),
        CheckConstraint(
            "(integration_event_id IS NULL) = (standard_result_json IS NULL)",
            name="ck_odoo_result_delivery_standard_payload",
        ),
    )
    result_delivery_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    acknowledgement_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("n8n_acknowledgement.acknowledgement_id"),
        nullable=True,
        unique=True,
    )
    runtime_result_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("n8n_runtime_result.result_id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    integration_event_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("integration_event.id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    standard_result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    result_public_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, unique=True, default=uuid4
    )
    originating_outbox_public_id: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    odoo_result_inbox_id: Mapped[str | None] = mapped_column(String(64))
    response_hash: Mapped[str | None] = mapped_column(String(64))
    last_error_class: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scope: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("integration_event.id")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint("scope", "key_hash", name="uq_idempotency_scope_key"),
    )


class PublisherNonce(Base):
    __tablename__ = "publisher_nonce"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    signed_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class PublisherAcknowledgement(Base):
    __tablename__ = "publisher_acknowledgement"
    acknowledgement_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    acknowledgement: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SecurityRejection(Base):
    __tablename__ = "security_rejection"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    claimed_publisher: Mapped[str | None] = mapped_column(String(128))
    authentication_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="UNVERIFIED"
    )
    key_id: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip_classification: Mapped[str] = mapped_column(String(16), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        CheckConstraint(
            "authentication_state = 'UNVERIFIED'",
            name="ck_security_rejection_unverified",
        ),
    )


class InvalidEventQuarantine(Base):
    __tablename__ = "invalid_event_quarantine"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    server_correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    client_correlation_id: Mapped[str | None] = mapped_column(String(128))
    claimed_source: Mapped[str | None] = mapped_column(String(64))
    claimed_publisher_identity: Mapped[str | None] = mapped_column(String(128))
    authenticated_publisher_id: Mapped[str] = mapped_column(String(128), nullable=False)
    authentication_state: Mapped[str] = mapped_column(String(24), nullable=False)
    authentication_key_id: Mapped[str | None] = mapped_column(String(64))
    original_signature_verification: Mapped[str] = mapped_column(
        String(24), nullable=False
    )
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_payload: Mapped[bytes | None] = mapped_column(LargeBinary)
    encryption_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    encryption_key_version: Mapped[str | None] = mapped_column(String(32))
    sanitized_preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    business_unit: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING_REVIEW"
    )
    review_owner: Mapped[str | None] = mapped_column(String(128))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(128))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replayed_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("integration_event.id")
    )
    replay_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    retention_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        CheckConstraint("replay_count >= 0", name="ck_quarantine_replay_count"),
        CheckConstraint("occurrence_count >= 1", name="ck_quarantine_occurrence_count"),
        CheckConstraint(
            "retention_deadline > received_at", name="ck_quarantine_retention"
        ),
        CheckConstraint("record_version >= 1", name="ck_quarantine_record_version"),
        CheckConstraint(
            "(review_owner IS NULL) = (reviewed_at IS NULL)",
            name="ck_quarantine_review_consistency",
        ),
        CheckConstraint(
            "(resolved_by IS NULL) = (resolved_at IS NULL)",
            name="ck_quarantine_resolution_consistency",
        ),
        CheckConstraint(
            "replayed_event_id IS NULL OR (authentication_state = 'VERIFIED' AND "
            "status = 'REPLAYED' AND resolved_at IS NOT NULL)",
            name="ck_quarantine_replay_eligibility",
        ),
        CheckConstraint(
            "status IN ('PENDING_REVIEW','UNDER_REVIEW','CORRECTABLE',"
            "'REPLAY_APPROVED','REPLAYING','REPLAYED','RESOLVED_NO_REPLAY',"
            "'EXPIRED','REJECTED')",
            name="ck_quarantine_state",
        ),
        CheckConstraint(
            "authentication_state = 'VERIFIED' AND "
            "original_signature_verification = 'VERIFIED'",
            name="ck_quarantine_verified_auth",
        ),
        CheckConstraint(
            "(encrypted_payload IS NULL AND encryption_nonce IS NULL AND "
            "encryption_key_version IS NULL) OR "
            "(encrypted_payload IS NOT NULL AND encryption_nonce IS NOT NULL AND "
            "encryption_key_version IS NOT NULL)",
            name="ck_quarantine_encryption_fields",
        ),
        Index("ix_quarantine_status_received", "status", "received_at"),
        Index(
            "ix_quarantine_publisher_received",
            "authenticated_publisher_id",
            "received_at",
        ),
        Index("ix_quarantine_correlation", "server_correlation_id"),
        Index(
            "ix_quarantine_retention_active",
            "retention_deadline",
            postgresql_where=text("legal_hold = false"),
        ),
        Index("ix_quarantine_fingerprint", "payload_fingerprint"),
    )


class QuarantineCorrection(Base):
    __tablename__ = "quarantine_correction"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    quarantine_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("invalid_event_quarantine.id", ondelete="RESTRICT"),
        nullable=False,
    )
    correction_version: Mapped[int] = mapped_column(Integer, nullable=False)
    correction_reason: Mapped[str] = mapped_column(String(512), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(128), nullable=False)
    derived_correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(32), nullable=False)
    sanitized_diff: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "quarantine_id",
            "correction_version",
            name="uq_quarantine_correction_version",
        ),
        CheckConstraint(
            "correction_version >= 1", name="ck_quarantine_correction_version"
        ),
    )


class EventInbox(Base):
    __tablename__ = "event_inbox"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    correlation_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(24), default="accepted")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class OutboxEvent(Base):
    __tablename__ = "outbox_event"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    topic: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replay_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SyncJob(Base):
    __tablename__ = "sync_job"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    job_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    last_error: Mapped[str | None] = mapped_column(Text)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookDelivery(Base):
    __tablename__ = "webhook_delivery"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    target: Mapped[str] = mapped_column(String(128))
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_event"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    action: Mapped[str] = mapped_column(String(128))
    subject: Mapped[str] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(32))
    redacted_payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PolicyDecision(Base):
    __tablename__ = "policy_decision"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    policy: Mapped[str] = mapped_column(String(128))
    allowed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    context: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class OrchestrationRequest(Base):
    __tablename__ = "orchestration_request"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_uid: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    business_unit: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    subject_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    department_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    team_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    supervisor_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    requested_resources: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="disabled")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CredentialGrant(Base):
    __tablename__ = "credential_grant"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    orchestration_request_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("orchestration_request.id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_type: Mapped[str] = mapped_column(String(32), nullable=False)
    vault_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    retrieval_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LeadSyncRequest(Base):
    __tablename__ = "lead_sync_request"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    source_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    business_unit: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    campaign_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    list_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="disabled")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ReconciliationCheckpoint(Base):
    __tablename__ = "reconciliation_checkpoint"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    source: Mapped[str] = mapped_column(String(64), unique=True)
    cursor: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(24), default="idle")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TransferPolicyDecision(Base):
    __tablename__ = "transfer_policy_decision"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    transfer_id: Mapped[str] = mapped_column(String(128))
    allowed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SystemHealthSnapshot(Base):
    __tablename__ = "system_health_snapshot"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    component: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class TelephonyExtensionPool(Base):
    __tablename__ = "telephony_extension_pool"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    business_unit: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    role_class: Mapped[str] = mapped_column(String(32), nullable=False)
    range_start: Mapped[int] = mapped_column(Integer, nullable=False)
    range_end: Mapped[int] = mapped_column(Integer, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    __table_args__ = (
        CheckConstraint("range_start >= 6100", name="ck_telephony_pool_start"),
        CheckConstraint("range_end <= 9999", name="ck_telephony_pool_end"),
        CheckConstraint("range_start <= range_end", name="ck_telephony_pool_order"),
    )


class CampaignExtensionAllocation(Base):
    """Authoritative immutable campaign extension-block ledger."""

    __tablename__ = "campaign_extension_allocation"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    campaign_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    allocation_public_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    extension_start: Mapped[int] = mapped_column(Integer, nullable=False)
    extension_end: Mapped[int] = mapped_column(Integer, nullable=False)
    extension_range: Mapped[Any] = mapped_column(
        INT4RANGE,
        Computed(
            "int4range(extension_start, extension_end, '[]')",
            persisted=True,
        ),
        nullable=False,
    )
    allocation_status: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default="PROPOSED"
    )
    allocated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128))
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_change_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    __table_args__ = (
        CheckConstraint(
            "extension_start >= 6100",
            name="ck_campaign_extension_allocation_start",
        ),
        CheckConstraint(
            "extension_end <= 9999",
            name="ck_campaign_extension_allocation_end",
        ),
        CheckConstraint(
            "extension_start <= extension_end",
            name="ck_campaign_extension_allocation_order",
        ),
        CheckConstraint(
            "campaign_number > 0 AND campaign_number % 100 = 0",
            name="ck_campaign_extension_allocation_number",
        ),
        CheckConstraint(
            "allocation_status IN "
            "('PROPOSED','RESERVED_DISABLED','ACTIVE','PAUSED','RETIRED')",
            name="ck_campaign_extension_allocation_status",
        ),
        ExcludeConstraint(
            ("extension_range", "&&"),
            using="gist",
            name="ex_campaign_extension_allocation_no_overlap",
        ),
    )


class CampaignRegistry(Base):
    __tablename__ = "campaign_registry"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    campaign_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    campaign_code: Mapped[str] = mapped_column(String(3), nullable=False, unique=True)
    campaign_public_id: Mapped[str] = mapped_column(
        String(32), nullable=False, unique=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    vicidial_campaign_id: Mapped[str] = mapped_column(
        String(8), nullable=False, unique=True
    )
    agent_group: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    dialplan_context: Mapped[str] = mapped_column(
        String(80), nullable=False, unique=True
    )
    parent_campaign_number: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("campaign_registry.campaign_number")
    )
    extension_allocation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("campaign_extension_allocation.id"),
        nullable=False,
        unique=True,
    )
    registry_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="PROPOSED_DISABLED"
    )
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_change_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CampaignObjectIdentity(Base):
    __tablename__ = "campaign_object_identity"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    campaign_number: Mapped[int] = mapped_column(
        Integer, ForeignKey("campaign_registry.campaign_number"), nullable=False
    )
    identity_type: Mapped[str] = mapped_column(String(24), nullable=False)
    sequence_value: Mapped[int] = mapped_column(BigInteger, nullable=False)
    public_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True)
    full_alias: Mapped[str | None] = mapped_column(String(112), unique=True)
    source_system: Mapped[str] = mapped_column(String(32), nullable=False)
    source_object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    identity_state: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default="ID_ASSIGNED"
    )
    dialing_state: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default="NOT_ELIGIBLE"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    __table_args__ = (
        UniqueConstraint(
            "campaign_number",
            "identity_type",
            "sequence_value",
            name="uq_campaign_object_identity_sequence",
        ),
        UniqueConstraint(
            "source_system",
            "source_object_id",
            "identity_type",
            name="uq_campaign_object_identity_source",
        ),
    )


class CampaignSearchAlias(Base):
    __tablename__ = "campaign_search_alias"
    alias: Mapped[str] = mapped_column(String(160), primary_key=True)
    campaign_number: Mapped[int] = mapped_column(
        Integer, ForeignKey("campaign_registry.campaign_number"), nullable=False
    )
    object_identity_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("campaign_object_identity.id")
    )
    alias_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CampaignFeatureGate(Base):
    __tablename__ = "campaign_feature_gate"
    campaign_number: Mapped[int] = mapped_column(
        Integer, ForeignKey("campaign_registry.campaign_number"), primary_key=True
    )
    feature_name: Mapped[str] = mapped_column(String(48), primary_key=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="DISABLED"
    )
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CampaignActivationAudit(Base):
    __tablename__ = "campaign_activation_audit"
    activation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_number: Mapped[int] = mapped_column(
        Integer, ForeignKey("campaign_registry.campaign_number"), nullable=False
    )
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TelephonyExtensionReservation(Base):
    __tablename__ = "telephony_extension_reservation"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    extension: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    employee_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    pool_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("telephony_extension_pool.id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="RESERVED")
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    reserved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("extension <> 6101", name="ck_telephony_reservation_6101"),
        CheckConstraint("extension <> 1001", name="ck_telephony_reservation_1001"),
        CheckConstraint(
            "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED','RELEASED','EXPIRED','COOLDOWN')",
            name="ck_telephony_reservation_state",
        ),
        Index(
            "uq_telephony_active_extension",
            "extension",
            unique=True,
            postgresql_where=text(
                "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED','COOLDOWN')"
            ),
        ),
        Index(
            "uq_telephony_active_employee",
            "employee_id",
            unique=True,
            postgresql_where=text(
                "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED')"
            ),
        ),
    )


class TelephonyProvisioningSaga(Base):
    __tablename__ = "telephony_provisioning_saga"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    employee_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    business_unit: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    extension: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    correlation_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    record_environment: Mapped[str] = mapped_column(
        String(16), nullable=False, default="PRODUCTION"
    )
    test_run_id: Mapped[str | None] = mapped_column(String(128), index=True)
    causation_id: Mapped[str | None] = mapped_column(String(128), index=True)
    policy_hash: Mapped[str | None] = mapped_column(String(64))
    approved_odoo_request: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    credential_reference: Mapped[str | None] = mapped_column(String(255))
    completed_steps: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        CheckConstraint("version >= 1", name="ck_telephony_saga_version"),
        CheckConstraint(
            "record_environment IN ('PRODUCTION','STAGING','TEST')",
            name="ck_telephony_saga_environment",
        ),
        CheckConstraint(
            "(record_environment = 'PRODUCTION' AND test_run_id IS NULL) OR "
            "(record_environment IN ('STAGING','TEST') AND "
            "test_run_id IS NOT NULL AND causation_id IS NOT NULL AND "
            "policy_hash IS NOT NULL)",
            name="ck_telephony_saga_test_binding",
        ),
        CheckConstraint(
            "state IN ('DRAFT','PENDING_APPROVAL','APPROVED','INVENTORY_CHECK','RESERVED',"
            "'PROVISIONING','DISABLED_READY','ACTIVATION_PENDING','ACTIVE','FAILED',"
            "'ROLLED_BACK','SUSPENDING','SUSPENDED','DEPROVISIONING','COOLDOWN')",
            name="ck_telephony_saga_state",
        ),
    )


class TelephonyCallLifecycle(Base):
    __tablename__ = "telephony_call_lifecycle"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    correlation_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    linked_id: Mapped[str | None] = mapped_column(String(128), index=True)
    primary_unique_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="STARTED"
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disposition: Mapped[str | None] = mapped_column(String(64))
    hangup_cause: Mapped[str | None] = mapped_column(String(64))
    fine_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="requested"
    )
    fine_state_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hangup_leg: Mapped[str | None] = mapped_column(String(16))
    last_event_type: Mapped[str | None] = mapped_column(String(64))
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_extension: Mapped[str] = mapped_column(String(32), nullable=False)
    destination: Mapped[str] = mapped_column(String(64), nullable=False)
    dialplan_context: Mapped[str] = mapped_column(String(128), nullable=False)
    # Reference only, not a copy - Odoo (codestra_middleware_bridge) remains
    # the system of record for the lead/customer-profile record itself. Set
    # once at originate time from OriginateCallRequest.lead_model/lead_id;
    # null for calls with no CRM linkage (e.g. internal calls).
    lead_model: Mapped[str | None] = mapped_column(String(64))
    lead_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        CheckConstraint(
            "lifecycle_state IN ('STARTED','CONNECTED','ENDED')",
            name="ck_telephony_call_lifecycle_state",
        ),
        CheckConstraint(
            "fine_state IN ("
            "'requested','accepted','queued','dialing','ringing','answered',"
            "'connected','completed','failed','busy','no_answer','canceled',"
            "'rejected')",
            name="ck_telephony_call_fine_state",
        ),
        CheckConstraint(
            "hangup_leg IS NULL OR hangup_leg IN ('agent_leg','peer_leg')",
            name="ck_telephony_call_hangup_leg",
        ),
    )


class TelephonyCallLifecycleEvent(Base):
    __tablename__ = "telephony_call_lifecycle_event"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    call_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("telephony_call_lifecycle.id", ondelete="CASCADE"),
        nullable=False,
    )
    integration_event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("integration_event.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    original_event_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    unique_id: Mapped[str] = mapped_column(String(128), nullable=False)
    channel: Mapped[str] = mapped_column(String(255), nullable=False)
    incoming_state: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(16))
    resulting_state: Mapped[str] = mapped_column(String(16), nullable=False)
    transition_applied: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AgentCallState(Base):
    __tablename__ = "agent_call_state"
    call_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    business_unit_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    extension: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    asterisk_uniqueid: Mapped[str] = mapped_column(String(128), nullable=False)
    linkedid: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    state_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    context_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        UniqueConstraint(
            "extension", "sequence", name="uq_agent_call_state_extension_sequence"
        ),
        CheckConstraint("sequence >= 0", name="ck_agent_call_state_sequence"),
    )


class AgentCallEvent(Base):
    __tablename__ = "agent_call_event"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    call_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    business_unit_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    extension: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    asterisk_uniqueid: Mapped[str] = mapped_column(String(128), nullable=False)
    linkedid: Mapped[str] = mapped_column(String(128), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    transition_applied: Mapped[bool] = mapped_column(Boolean, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "call_id", "sequence", name="uq_agent_call_event_call_sequence"
        ),
        CheckConstraint("sequence >= 0", name="ck_agent_call_event_sequence"),
    )


class IntegrationService(Base):
    __tablename__ = "integration_service"
    service_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    service_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IntegrationCredentialReference(Base):
    __tablename__ = "integration_credential_reference"
    credential_reference_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    reference_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IntegrationEndpoint(Base):
    __tablename__ = "integration_endpoint"
    endpoint_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    service_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("integration_service.service_id", ondelete="RESTRICT"),
        nullable=False,
    )
    endpoint_key: Mapped[str] = mapped_column(String(96), nullable=False)
    api_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "service_id", "endpoint_key", "api_version", name="uq_endpoint_identity"
        ),
    )


class IntegrationEndpointVersion(Base):
    __tablename__ = "integration_endpoint_version"
    endpoint_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    endpoint_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("integration_endpoint.endpoint_id", ondelete="CASCADE"),
        nullable=False,
    )
    configuration_version: Mapped[int] = mapped_column(Integer, nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    path_template: Mapped[str] = mapped_column(String(512), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    content_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="application/json"
    )
    authentication_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    required_audience: Mapped[str] = mapped_column(String(128), nullable=False)
    required_scopes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    credential_reference_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tls_profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    timeout_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=10000)
    connection_timeout_ms: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3000
    )
    rate_limit_per_minute: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    concurrency_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    retry_class: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NO_RETRY"
    )
    retry_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redirects_allowed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    target_attestation_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    stale_read_safe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    configuration_checksum: Mapped[str] = mapped_column(String(71), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "configuration_version",
            name="uq_endpoint_configuration_version",
        ),
        CheckConstraint("configuration_version >= 1", name="ck_endpoint_version"),
        CheckConstraint("timeout_ms > 0", name="ck_endpoint_timeout"),
        CheckConstraint(
            "connection_timeout_ms > 0", name="ck_endpoint_connection_timeout"
        ),
        CheckConstraint("retry_limit >= 0", name="ck_endpoint_retry_limit"),
        CheckConstraint(
            "retry_class IN ('NO_RETRY','BOUNDED_TRANSIENT_RETRY','MANUAL_REPLAY_ONLY')",
            name="ck_endpoint_retry_class",
        ),
    )


class IntegrationRouteBinding(Base):
    __tablename__ = "integration_route_binding"
    binding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    endpoint_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("integration_endpoint_version.endpoint_version_id"),
        nullable=False,
    )
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    organization_scope: Mapped[str] = mapped_column(
        String(128), nullable=False, default=""
    )
    business_unit_scope: Mapped[str] = mapped_column(
        String(128), nullable=False, default=""
    )
    campaign_scope: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    workflow_scope: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    event_type_scope: Mapped[str] = mapped_column(
        String(128), nullable=False, default=""
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "environment",
            "endpoint_version_id",
            "organization_scope",
            "business_unit_scope",
            "campaign_scope",
            "workflow_scope",
            "event_type_scope",
            name="uq_route_binding_scope",
        ),
        Index(
            "ix_route_binding_lookup",
            "environment",
            "organization_scope",
            "business_unit_scope",
            "campaign_scope",
        ),
    )


class IntegrationSchemaVersion(Base):
    __tablename__ = "integration_schema_version"
    schema_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    service_key: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint_key: Mapped[str] = mapped_column(String(96), nullable=False)
    api_version: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    checksum: Mapped[str] = mapped_column(String(71), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    __table_args__ = (
        UniqueConstraint(
            "service_key",
            "endpoint_key",
            "api_version",
            name="uq_integration_schema_key",
        ),
    )


class IntegrationEndpointAudit(Base):
    __tablename__ = "integration_endpoint_audit"
    audit_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    endpoint_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    previous_checksum: Mapped[str | None] = mapped_column(String(71))
    new_checksum: Mapped[str] = mapped_column(String(71), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IntegrationRegistryGeneration(Base):
    __tablename__ = "integration_registry_generation"
    environment: Mapped[str] = mapped_column(String(32), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    configuration_checksum: Mapped[str] = mapped_column(String(71), nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    published_by: Mapped[str] = mapped_column(String(128), nullable=False)


class CallbackRecord(Base):
    """Canonical callback control state; customer CRM data remains in Odoo."""

    __tablename__ = "callback_record"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(128), nullable=False)
    contact_id: Mapped[str | None] = mapped_column(String(128))
    lead_id: Mapped[str | None] = mapped_column(String(128))
    opportunity_id: Mapped[str | None] = mapped_column(String(128))
    original_call_id: Mapped[str | None] = mapped_column(String(128))
    original_linkedid: Mapped[str | None] = mapped_column(String(128))
    assigned_agent_id: Mapped[str | None] = mapped_column(String(128))
    assigned_user_id: Mapped[str | None] = mapped_column(String(128))
    assigned_team_id: Mapped[str | None] = mapped_column(String(128))
    supervisor_id: Mapped[str | None] = mapped_column(String(128))
    phone_number: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_phone: Mapped[str] = mapped_column(String(32), nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    customer_timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="NORMAL")
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="SCHEDULED")
    desired_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SCHEDULED"
    )
    actual_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SCHEDULED"
    )
    reminder_email_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    reminder_popup_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    email_reminder_1_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    email_reminder_2_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    popup_reminder_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completion_disposition: Mapped[str | None] = mapped_column(String(64))
    completion_notes: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    sync_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    compliance_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    context_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        CheckConstraint(
            "assigned_agent_id IS NOT NULL OR assigned_team_id IS NOT NULL",
            name="ck_callback_owner",
        ),
        CheckConstraint(
            "version >= 1 AND attempt_count >= 0 AND max_attempts >= 1",
            name="ck_callback_counters",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_callback_tenant_idempotency"
        ),
        Index("ix_callback_due_claim", "state", "scheduled_at"),
        Index(
            "ix_callback_agent_queue",
            "tenant_id",
            "campaign_id",
            "assigned_agent_id",
            "scheduled_at",
        ),
        Index("ix_callback_phone", "tenant_id", "normalized_phone"),
        Index("ix_callback_correlation", "correlation_id"),
    )


class CallbackEvent(Base):
    __tablename__ = "callback_event"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    callback_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("callback_record.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        UniqueConstraint(
            "callback_id",
            "version",
            "event_type",
            name="uq_callback_event_version_type",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_callback_event_idempotency"
        ),
        Index("ix_callback_event_outbox", "published_at", "occurred_at"),
    )


class CallbackDelivery(Base):
    __tablename__ = "callback_delivery"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    callback_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("callback_record.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    callback_version: Mapped[int] = mapped_column(Integer, nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    message_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    provider_message_id: Mapped[str | None] = mapped_column(String(128))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        UniqueConstraint(
            "callback_id",
            "callback_version",
            "channel",
            "stage",
            name="uq_callback_delivery_stage",
        ),
        Index("ix_callback_delivery_retry", "status", "next_attempt_at"),
    )


AGENT_PROVISIONING_STATES = (
    "REQUESTED",
    "VALIDATING",
    "IDENTITY",
    "ENTITLEMENTS",
    "CHANNEL_PROVISIONING",
    "READBACK",
    "EFFECTIVE",
    "PARTIAL",
    "FAILED",
    "RECONCILING",
    "SUSPENDED",
    "REVOKED",
)


class AgentProvisioningRequest(Base):
    """One durable saga per Odoo "Provision" click (Mission 3).

    Odoo sends exactly one command here and polls/observes this row (and its
    AgentProvisioningStep children) for progress; Middleware alone decides
    how to reach EFFECTIVE across Keycloak, VICIdial, Klyrow, and Telnexa.
    No provider secret or raw credential is ever stored in this table or in
    AgentProvisioningStep - see keycloak_subject below, which is an opaque
    identifier, never a token.
    """

    __tablename__ = "agent_provisioning_request"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    employee_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    primary_email: Mapped[str] = mapped_column(String(255), nullable=False)
    campaigns_json: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    channels_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    telephony_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="REQUESTED")
    keycloak_subject: Mapped[str | None] = mapped_column(String(64))
    policy_revision: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    last_error_summary: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    __table_args__ = (
        CheckConstraint(
            "state IN ('" + "','".join(AGENT_PROVISIONING_STATES) + "')",
            name="ck_agent_provisioning_state",
        ),
        CheckConstraint("version >= 1", name="ck_agent_provisioning_version"),
        Index("ix_agent_provisioning_tenant_state", "tenant_id", "state"),
    )


class AgentProvisioningStep(Base):
    """Per-external-operation saga log, one row per attempt.

    Deliberately mirrors codestra.provisioning.step's field shape on the
    Odoo side (appolon1908-hue/Odoo, codestra_identity_provisioning) so the
    two systems describe the same saga in the same vocabulary:
    system/operation/attempt/state/external_reference/started_at/
    completed_at/readback_state/error_code/error_summary. Never stores
    provider secrets or raw tokens.
    """

    __tablename__ = "agent_provisioning_step"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_provisioning_request.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    system: Mapped[str] = mapped_column(String(32), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    external_reference: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    readback_state: Mapped[str | None] = mapped_column(String(32))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_summary: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    __table_args__ = (
        CheckConstraint(
            "system IN ('keycloak','vicidial','klyrow','telnexa','odoo')",
            name="ck_agent_provisioning_step_system",
        ),
        Index("ix_agent_provisioning_step_request", "request_id", "system", "attempt"),
    )


class AgentProvisioningAudit(Base):
    """Append-only state-transition ledger. No update/delete path exists."""

    __tablename__ = "agent_provisioning_audit"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_provisioning_request.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    from_state: Mapped[str] = mapped_column(String(24), nullable=False)
    to_state: Mapped[str] = mapped_column(String(24), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class OdooCampaignSaga(Base):
    """One saga per accepted Odoo campaign-control outbox event.

    The unique ``integration_event_id`` is the "exactly one saga row per
    event" guarantee; concurrent selectors lose on the constraint, not on a
    race. Saga status (dispatch lifecycle) and ``effective_state`` (what the
    adapter observed and Odoo was told) are deliberately separate columns.
    """

    __tablename__ = "odoo_campaign_saga"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','RESERVED','RETRY','COMPLETED','DEAD_LETTER')",
            name="ck_odoo_campaign_saga_status",
        ),
        CheckConstraint(
            "effective_state IS NULL OR effective_state IN "
            "('unknown','absent','provisioned_disabled','synthetic_tested','active','disabled')",
            name="ck_odoo_campaign_saga_effective_state",
        ),
        Index("ix_odoo_campaign_saga_claim", "status", "next_attempt_at"),
    )
    saga_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    integration_event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("integration_event.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    event_uuid: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    command_id: Mapped[str] = mapped_column(String(128), nullable=False)
    organization_public_id: Mapped[str] = mapped_column(String(128), nullable=False)
    business_unit_public_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_public_id: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration_version: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_class: Mapped[str | None] = mapped_column(String(64))
    effective_state: Mapped[str | None] = mapped_column(String(32))
    evidence_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    readback_idempotency_key: Mapped[str | None] = mapped_column(String(160))
    readback_attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    readback_id: Mapped[str | None] = mapped_column(String(128))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

class AgentProvisioningRepairIntent(Base):
    __tablename__ = "agent_provisioning_repair_intent"
    __table_args__ = (
        CheckConstraint(
            "state IN ('PROPOSED','AUTHORIZED','EXECUTING','SUCCEEDED','FAILED','CANCELLED')",
            name="ck_agent_repair_state",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["agent_provisioning_request.tenant_id", "agent_provisioning_request.id"],
            name="fk_agent_repair_tenant_request",
            ondelete="RESTRICT",
        ),
        Index(
            "ix_agent_repair_tenant_request",
            "tenant_id",
            "request_id",
            text("created_at DESC"),
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    request_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    drift_class: Mapped[str] = mapped_column(String(40), nullable=False)
    proposed_action: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="PROPOSED")
    effect_class: Mapped[str] = mapped_column(String(32), nullable=False, default="provider_mutation")
    authorized_by: Mapped[str | None] = mapped_column(String(255))
    result_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentWebrtcSession(Base):
    __tablename__ = "agent_webrtc_session"
    __table_args__ = (
        CheckConstraint(
            "state IN ('ISSUED','REGISTERING','REGISTERED','EXPIRED','REVOKED','FAILED')",
            name="ck_agent_webrtc_state",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["agent_provisioning_request.tenant_id", "agent_provisioning_request.id"],
            name="fk_agent_webrtc_tenant_request",
            ondelete="RESTRICT",
        ),
        Index(
            "uq_agent_webrtc_active_device",
            "tenant_id",
            "employee_id",
            unique=True,
            postgresql_where=text("state IN ('ISSUED','REGISTERING','REGISTERED')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    request_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    employee_id: Mapped[str] = mapped_column(String(128), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False)
    extension: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_reference: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="ISSUED")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
