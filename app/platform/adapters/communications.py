"""Shared communications adapter primitives plus the Evolution/WhatsApp boundary.

Email, SMS and WhatsApp share one normalized delivery vocabulary.  The
provider-specific transport remains thin; Command Core owns authorization,
idempotency, retry scheduling and the effect gate.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Protocol

from app.commands import CommandEnvelope, CommandOperation
from app.platform.adapter import (
    AdapterConfigurationError,
    AdapterContext,
    AdapterReadiness,
    AdapterResult,
    BaseAdapter,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)

_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")
_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class CommunicationChannel(StrEnum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    WHATSAPP = "WHATSAPP"


class DeliveryState(StrEnum):
    QUEUED = "QUEUED"
    ACCEPTED = "ACCEPTED"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CommunicationCommand:
    channel: CommunicationChannel
    recipient: str
    sender_identity: str
    content: str
    tenant_id: str
    campaign_id: str | None
    correlation_id: str
    metadata: Mapping[str, str | int | float | bool | None]

    @classmethod
    def whatsapp(cls, command: CommandEnvelope) -> "CommunicationCommand":
        payload = command.payload
        recipient = payload.get("recipient") or payload.get("destination")
        sender = payload.get("sender_identity") or payload.get("instance")
        content = payload.get("text") or payload.get("body")
        campaign = payload.get("campaign_id")
        if not isinstance(recipient, str) or _E164.fullmatch(recipient) is None:
            raise ValueError("invalid_whatsapp_recipient")
        if not isinstance(sender, str) or _SAFE_INSTANCE.fullmatch(sender) is None:
            raise ValueError("invalid_whatsapp_sender")
        if not isinstance(content, str) or not (1 <= len(content.encode("utf-8")) <= 4096):
            raise ValueError("invalid_whatsapp_content")
        if campaign is not None and (not isinstance(campaign, str) or len(campaign) > 128):
            raise ValueError("invalid_campaign")
        metadata = payload.get("metadata")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, Mapping):
            raise ValueError("invalid_metadata")
        safe: dict[str, str | int | float | bool | None] = {}
        for key, value in metadata.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("invalid_metadata")
            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[key] = value
            else:
                raise ValueError("invalid_metadata")
        return cls(
            channel=CommunicationChannel.WHATSAPP,
            recipient=recipient,
            sender_identity=sender,
            content=content,
            tenant_id=command.tenant_id,
            campaign_id=campaign,
            correlation_id=command.correlation_id,
            metadata=safe,
        )


@dataclass(frozen=True)
class CommunicationResult:
    provider: str
    provider_message_id: str
    status: DeliveryState
    failure_code: str | None = None
    retry_hint: str | None = None
    readback_required: bool = True


class CommunicationTransport(Protocol):
    async def send(self, command: CommunicationCommand, context: AdapterContext) -> CommunicationResult: ...
    async def readback(self, provider_reference: str, *, tenant_id: str, context: AdapterContext) -> CommunicationResult | None: ...


class SyntheticCommunicationSink:
    """Deterministic local sink used only for TEST_SYN/local certification."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        self._rows: dict[tuple[str, str], CommunicationResult] = {}

    async def send(self, command: CommunicationCommand, context: AdapterContext) -> CommunicationResult:
        digest = hashlib.sha256(
            f"{command.tenant_id}:{context.command_id}:{context.correlation_id}".encode()
        ).hexdigest()[:32]
        ref = f"syn-{self.provider}-{digest}"
        key = (command.tenant_id, ref)
        existing = self._rows.get(key)
        if existing is not None:
            return existing
        result = CommunicationResult(
            provider=self.provider,
            provider_message_id=ref,
            status=DeliveryState.DELIVERED,
            readback_required=True,
        )
        self._rows[key] = result
        return result

    async def readback(self, provider_reference: str, *, tenant_id: str, context: AdapterContext) -> CommunicationResult | None:
        del context
        return self._rows.get((tenant_id, provider_reference))


@dataclass
class EvolutionWhatsAppAdapter(BaseAdapter):
    """Evolution/WhatsApp adapter.

    Live transport is injected by the runtime.  Without it the adapter fails
    closed. TEST_SYN uses a deterministic local sink and never reaches a real
    WhatsApp instance.
    """

    adapter_id: str = "evolution-whatsapp"
    provider_family: str = "whatsapp"
    connector_ids: tuple[str, ...] = ("evolution-whatsapp",)
    served_capabilities: tuple[str, ...] = ("WHATSAPP_DELIVERY",)
    version: str = "v1/1.0"
    supports_status: bool = True
    supports_readback: bool = True
    supports_cancel: bool = False
    safe_reexecution: bool = False
    external_effect: bool = True
    transport: CommunicationTransport | None = None
    synthetic: SyntheticCommunicationSink | None = None

    COMMAND_TYPE = "whatsapp.message.send.v1"

    def validate_config(self) -> None:
        BaseAdapter.validate_config(self)
        if self.transport is None and self.synthetic is None:
            raise AdapterConfigurationError(
                "evolution-whatsapp: no provider transport or synthetic sink configured"
            )

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        if context.test_syn and self.synthetic is not None:
            return AdapterReadiness(True, "synthetic sink ready")
        return AdapterReadiness(
            self.transport is not None,
            "provider transport configured" if self.transport is not None else "provider transport unavailable",
        )

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        if command.command_type != self.COMMAND_TYPE:
            return AdapterResult(
                Outcome.UNSUPPORTED,
                error_class=ErrorClass.UNSUPPORTED,
                safe_error_code="CAPABILITY_UNSUPPORTED",
            )
        try:
            normalized = CommunicationCommand.whatsapp(command)
        except ValueError as exc:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code=str(exc),
            )
        transport = self.synthetic if context.test_syn else self.transport
        if transport is None:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="DEPENDENCY_UNAVAILABLE",
            )
        try:
            result = await transport.send(normalized, context)
        except TimeoutError:
            return AdapterResult(
                Outcome.UNKNOWN,
                error_class=ErrorClass.AMBIGUOUS,
                safe_error_code="PROVIDER_TIMEOUT",
            )
        except Exception as exc:  # provider outcome may be unknown
            return AdapterResult(
                Outcome.UNKNOWN,
                error_class=ErrorClass.AMBIGUOUS,
                safe_error_code=type(exc).__name__,
            )
        outcome = (
            Outcome.ACCEPTED
            if result.status in {DeliveryState.QUEUED, DeliveryState.ACCEPTED, DeliveryState.SENT, DeliveryState.DELIVERED}
            else Outcome.REJECTED
        )
        return AdapterResult(
            outcome,
            provider_operation_id=result.provider_message_id,
            error_class=None if outcome is Outcome.ACCEPTED else ErrorClass.NON_RETRYABLE,
            safe_error_code=result.failure_code,
            safe_details={"provider_status": result.status.value},
        )

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        reference = operation.provider_operation_id
        if not reference:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="provider_reference_missing")
        transport = self.synthetic if context.test_syn else self.transport
        if transport is None:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code="DEPENDENCY_UNAVAILABLE")
        try:
            result = await transport.readback(reference, tenant_id=context.tenant_id, context=context)
        except Exception as exc:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        if result is None:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="provider_reference_not_found")
        mapping = {
            DeliveryState.QUEUED: ReadbackStatus.PENDING,
            DeliveryState.ACCEPTED: ReadbackStatus.ACCEPTED,
            DeliveryState.SENT: ReadbackStatus.RUNNING,
            DeliveryState.DELIVERED: ReadbackStatus.MATCHED,
            DeliveryState.FAILED: ReadbackStatus.FAILED,
            DeliveryState.REJECTED: ReadbackStatus.MISMATCH,
            DeliveryState.EXPIRED: ReadbackStatus.FAILED,
            DeliveryState.CANCELLED: ReadbackStatus.CANCELLED,
            DeliveryState.UNKNOWN: ReadbackStatus.UNKNOWN,
        }
        return ReadbackResult(
            mapping[result.status],
            provider_operation_id=result.provider_message_id,
            evidence={"delivery_state": result.status.value, "provider": result.provider},
            safe_error_code=result.failure_code,
        )

    async def reconcile(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        return await self.readback(operation, context)
