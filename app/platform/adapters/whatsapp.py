"""WhatsApp provider adapter for the Middleware V3 command kernel.

Middleware owns authorization, idempotency, durable outbox, retry, DLQ/replay,
reconciliation and audit. This adapter only translates one accepted V3 command
into the internal Codestra Evolution provider-adapter contract and normalizes
provider readback.
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import quote

import httpx

from app.commands import CommandEnvelope, CommandOperation
from app.core.config import Settings
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


class WhatsAppProviderAdapter(BaseAdapter):
    adapter_id = "evolution-whatsapp"
    version = "codestra-whatsapp/0.1"
    provider_family = "whatsapp"
    connector_ids = ("evolution-whatsapp",)
    served_capabilities = ("WHATSAPP_DELIVERY",)
    supports_readback = True
    supports_status = True
    supports_cancel = False
    safe_reexecution = False
    external_effect = True

    command_type = "whatsapp.message.send.v1"

    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.evolution_whatsapp_base_url.strip().rstrip("/")
        self.service_token = settings.evolution_whatsapp_service_token.strip()
        self.provider = settings.evolution_whatsapp_provider.strip().lower() or "evolution"
        self.default_instance_id = settings.evolution_whatsapp_instance_id.strip()

    def validate_config(self) -> None:
        super().validate_config()
        if not self.base_url.startswith(("http://", "https://")):
            raise AdapterConfigurationError("evolution-whatsapp: EVOLUTION_WHATSAPP_BASE_URL is required")
        if not self.service_token:
            raise AdapterConfigurationError("evolution-whatsapp: EVOLUTION_WHATSAPP_SERVICE_TOKEN is required")
        if self.provider not in {"evolution", "meta"}:
            raise AdapterConfigurationError("evolution-whatsapp: provider must be evolution or meta")

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        if context.http is None:
            return AdapterReadiness(False, "shared_http_unavailable")
        try:
            response = await context.http.get(
                f"{self.base_url}/readyz",
                headers=context.outbound_headers(),
                timeout=context.timeout_seconds,
            )
        except httpx.HTTPError as exc:
            return AdapterReadiness(False, type(exc).__name__)
        if response.status_code != 200:
            return AdapterReadiness(False, f"http_{response.status_code}")
        try:
            body = response.json()
        except ValueError:
            return AdapterReadiness(False, "invalid_json")
        return AdapterReadiness(body.get("status") == "ready", "provider_adapter_ready")

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        if command.command_type != self.command_type:
            return AdapterResult(
                Outcome.UNSUPPORTED,
                error_class=ErrorClass.UNSUPPORTED,
                safe_error_code="unsupported_command_type",
            )
        if context.http is None:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="shared_http_unavailable",
            )

        payload = dict(command.payload)
        recipient = payload.get("recipient")
        message = payload.get("message")
        campaign_id = payload.get("campaign_id")
        if not isinstance(recipient, str) or not recipient.strip():
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="recipient_required",
            )
        if not isinstance(message, Mapping):
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="message_required",
            )
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="campaign_id_required",
            )

        instance_id = payload.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id.strip():
            instance_id = self.default_instance_id

        business_context = dict(payload.get("business_context") or {})
        business_context.setdefault("campaign_id", campaign_id.strip())
        body: dict[str, Any] = {
            "command_id": str(command.command_id),
            "tenant_id": command.tenant_id,
            "correlation_id": command.correlation_id,
            "idempotency_key": command.idempotency_key,
            "campaign_id": campaign_id.strip(),
            "provider": self.provider,
            "recipient": recipient.strip(),
            "message": dict(message),
            "business_context": business_context,
        }
        if instance_id:
            body["instance_id"] = instance_id

        headers = {
            **context.outbound_headers(),
            "Authorization": f"Bearer {self.service_token}",
            "X-Tenant-ID": command.tenant_id,
            "X-Command-ID": str(command.command_id),
            "Idempotency-Key": command.idempotency_key,
            "Content-Type": "application/json",
        }
        try:
            response = await context.http.post(
                f"{self.base_url}/internal/v1/whatsapp/transport/messages",
                headers=headers,
                json=body,
                timeout=context.timeout_seconds,
            )
        except Exception as exc:  # provider outcome may be ambiguous after transmission
            error_class = self.classify_error(exc)
            outcome = Outcome.TRANSIENT if error_class is ErrorClass.RETRYABLE_BEFORE_EFFECT else Outcome.UNKNOWN
            return AdapterResult(
                outcome,
                error_class=error_class,
                safe_error_code=type(exc).__name__,
            )

        return self._normalize_execute_response(response)

    def _normalize_execute_response(self, response: httpx.Response) -> AdapterResult:
        if response.status_code == 202:
            try:
                body = response.json()
            except ValueError:
                return AdapterResult(
                    Outcome.UNKNOWN,
                    error_class=ErrorClass.AMBIGUOUS,
                    safe_error_code="invalid_provider_json",
                )
            result = body.get("result") if isinstance(body, Mapping) else None
            provider_message_id = result.get("provider_message_id") if isinstance(result, Mapping) else None
            if not isinstance(provider_message_id, str) or not provider_message_id:
                return AdapterResult(
                    Outcome.UNKNOWN,
                    error_class=ErrorClass.AMBIGUOUS,
                    safe_error_code="provider_message_id_missing",
                )
            return AdapterResult(
                Outcome.ACCEPTED,
                provider_operation_id=provider_message_id,
                safe_details={"provider": self.provider},
            )

        if response.status_code in {401, 403}:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.PROVIDER_AUTH,
                safe_error_code=f"adapter_http_{response.status_code}",
            )
        if response.status_code in {408, 425, 429, 502, 503, 504}:
            return AdapterResult(
                Outcome.TRANSIENT,
                error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT,
                safe_error_code=f"adapter_http_{response.status_code}",
            )
        if 400 <= response.status_code < 500:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code=f"adapter_http_{response.status_code}",
            )
        return AdapterResult(
            Outcome.UNKNOWN,
            error_class=ErrorClass.AMBIGUOUS,
            safe_error_code=f"adapter_http_{response.status_code}",
        )

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        provider_id = operation.provider_operation_id
        if not provider_id:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="provider_message_id_missing")
        if context.http is None:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code="shared_http_unavailable")

        headers = {
            **context.outbound_headers(),
            "Authorization": f"Bearer {self.service_token}",
            "X-Tenant-ID": operation.tenant_id,
            "X-Command-ID": str(operation.command_id),
        }
        try:
            response = await context.http.get(
                f"{self.base_url}/internal/v1/whatsapp/transport/messages/{quote(provider_id, safe='')}",
                headers=headers,
                timeout=context.timeout_seconds,
            )
        except httpx.HTTPError as exc:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)

        if response.status_code == 404:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, provider_operation_id=provider_id)
        if response.status_code != 200:
            return ReadbackResult(
                ReadbackStatus.UNAVAILABLE,
                provider_operation_id=provider_id,
                safe_error_code=f"adapter_http_{response.status_code}",
            )
        try:
            body = response.json()
        except ValueError:
            return ReadbackResult(
                ReadbackStatus.UNAVAILABLE,
                provider_operation_id=provider_id,
                safe_error_code="invalid_provider_json",
            )

        state = str(body.get("state", "")).upper()
        evidence = {"state": state, "provider": str(body.get("provider") or self.provider)}
        if state in {"DELIVERED", "READ"}:
            return ReadbackResult(
                ReadbackStatus.MATCHED,
                provider_operation_id=provider_id,
                evidence=evidence,
            )
        if state == "FAILED":
            return ReadbackResult(
                ReadbackStatus.MISMATCH,
                provider_operation_id=provider_id,
                evidence=evidence,
                safe_error_code="provider_failed",
            )
        return ReadbackResult(
            ReadbackStatus.UNAVAILABLE,
            provider_operation_id=provider_id,
            evidence=evidence,
            safe_error_code=f"provider_{state.lower() or 'unknown'}",
        )

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        readback = await self.readback(operation, context)
        if readback.status is ReadbackStatus.MATCHED:
            return AdapterResult(Outcome.COMPLETED, provider_operation_id=readback.provider_operation_id)
        if readback.status is ReadbackStatus.MISMATCH:
            return AdapterResult(
                Outcome.REJECTED,
                provider_operation_id=readback.provider_operation_id,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code=readback.safe_error_code,
            )
        return AdapterResult(
            Outcome.UNKNOWN,
            provider_operation_id=readback.provider_operation_id,
            error_class=ErrorClass.AMBIGUOUS,
            safe_error_code=readback.safe_error_code,
        )
