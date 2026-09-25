"""Bridge the command-kernel Adapter contract through the shared Section 2 runtime.

This is deliberately translation-only: authorization, safety, retry,
idempotency and durability remain outside provider code.
"""
from __future__ import annotations

from typing import Any, Mapping

from app.commands import CommandEnvelope, CommandOperation
from app.platform.adapter import (
    Adapter,
    AdapterContext,
    AdapterResult,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)
from middleware.connector_runtime.execution import (
    Connector,
    ConnectorCapability,
    ConnectorDescriptor,
    ConnectorError,
    ConnectorResult,
    EffectClass,
    ExecutionContext,
    ProviderErrorCode,
)


def _effect(provider_family: str, operation: str) -> EffectClass:
    if operation.endswith(".read") or ".read." in operation or operation.endswith(".status"):
        return EffectClass.READ_ONLY
    family = provider_family.lower()
    if family in {"email", "sms", "whatsapp"}:
        return EffectClass.COMMUNICATION
    if family in {"telephony", "vicidial"}:
        return EffectClass.TELEPHONY
    if family == "n8n":
        return EffectClass.AUTOMATION
    if "provision" in operation or family == "provisioning":
        return EffectClass.PROVISIONING
    return EffectClass.EXTERNAL_MUTATION


def _provider_error(result: AdapterResult) -> ConnectorError | None:
    if result.outcome in {Outcome.ACCEPTED, Outcome.COMPLETED, Outcome.CANCELLED}:
        return None
    code: str | ProviderErrorCode
    if result.error_class is ErrorClass.PROVIDER_AUTH:
        code = ProviderErrorCode.PROVIDER_AUTH_FAILED
    elif result.error_class is ErrorClass.PROVIDER_RATE_LIMITED:
        code = ProviderErrorCode.PROVIDER_RATE_LIMITED
    elif result.error_class is ErrorClass.RETRYABLE_BEFORE_EFFECT:
        code = ProviderErrorCode.DEPENDENCY_UNAVAILABLE
    elif result.error_class is ErrorClass.UNSUPPORTED:
        code = ProviderErrorCode.CAPABILITY_UNSUPPORTED
    elif result.error_class is ErrorClass.AMBIGUOUS:
        code = ProviderErrorCode.REMOTE_STATE_UNKNOWN
    else:
        code = ProviderErrorCode.PROVIDER_REJECTED
    return ConnectorError(
        code,
        result.safe_error_code or str(code),
        retryable=result.error_class in {ErrorClass.RETRYABLE_BEFORE_EFFECT, ErrorClass.PROVIDER_RATE_LIMITED},
    )


def _connector_status(result: AdapterResult) -> tuple[bool, str, bool]:
    if result.outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}:
        return True, result.outcome.value, False
    if result.outcome is Outcome.UNKNOWN:
        return False, "UNKNOWN", True
    if result.outcome is Outcome.TRANSIENT:
        return False, "RETRYABLE", False
    return False, result.outcome.value, False


class KernelAdapterConnector(Connector):
    """Expose one existing provider adapter as a Section 2 Connector."""

    def __init__(self, adapter: Adapter, command_prefixes: tuple[str, ...]) -> None:
        self.adapter = adapter
        advertised = adapter.capabilities()
        self.descriptor = ConnectorDescriptor(
            connector_id=advertised.connector_ids[0],
            provider=advertised.provider_family,
            version=advertised.version,
            capabilities=tuple(
                ConnectorCapability(prefix, _effect(advertised.provider_family, prefix))
                for prefix in command_prefixes
            ),
            environments=frozenset({"development", "local", "test", "staging", "production"}),
            dependencies=("CommandCore", "Authorization", "EffectGate"),
            enabled=True,
        )

    async def health(self, context: ExecutionContext) -> ConnectorResult:
        readiness = await self.adapter.readiness(_adapter_context(context))
        return ConnectorResult(
            readiness.ready,
            "healthy" if readiness.ready else "unavailable",
            data={"detail": readiness.detail[:128]},
        )

    async def execute(
        self,
        operation: str,
        payload: Mapping[str, Any],
        context: ExecutionContext,
    ) -> ConnectorResult:
        raw = payload.get("_command")
        command = raw if isinstance(raw, CommandEnvelope) else CommandEnvelope.model_validate(raw)
        adapter_result = await self.adapter.execute(command, _adapter_context(context, payload=command.payload))
        ok, status, reconcile = _connector_status(adapter_result)
        return ConnectorResult(
            ok=ok,
            status=status,
            data=dict(adapter_result.safe_details),
            provider_reference=adapter_result.provider_operation_id,
            provider_status=status,
            retry_hint={
                "retryable": adapter_result.error_class in {
                    ErrorClass.RETRYABLE_BEFORE_EFFECT,
                    ErrorClass.PROVIDER_RATE_LIMITED,
                }
            },
            reconciliation_required=reconcile,
            error=_provider_error(adapter_result),
        )

    async def readback(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        operation = _operation(context, reference)
        result = await self.adapter.readback(operation, _adapter_context(context))
        return _readback_connector_result(result, reference)

    async def reconcile(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        operation = _operation(context, reference)
        result = await self.adapter.reconcile(operation, _adapter_context(context))
        return _readback_connector_result(result, reference)

    async def cancel(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        operation = _operation(context, reference)
        result = await self.adapter.cancel(operation, _adapter_context(context))
        ok, status, reconcile = _connector_status(result)
        return ConnectorResult(
            ok=ok,
            status=status,
            provider_reference=result.provider_operation_id or reference,
            reconciliation_required=reconcile,
            error=_provider_error(result),
        )


def _adapter_context(
    context: ExecutionContext,
    *,
    payload: Mapping[str, Any] | None = None,
) -> AdapterContext:
    return AdapterContext(
        tenant_id=context.tenant_id,
        command_id=context.command_id,
        correlation_id=context.correlation_id,
        attempt=context.attempt,
        timeout_seconds=context.timeout_seconds,
        environment=context.environment,
        deployment_sha="shared-runtime",
        trace_context={},
        test_syn=context.tenant_id == "TEST_SYN",
        payload=dict(payload or context.payload),
        http=context.http,
    )


def _operation(context: ExecutionContext, reference: str) -> CommandOperation:
    raw = context.operation_snapshot
    if not isinstance(raw, Mapping) or not raw:
        raise RuntimeError("operation_record_required")
    operation = CommandOperation.model_validate(raw)
    if operation.provider_operation_id is None and reference:
        operation = operation.model_copy(update={"provider_operation_id": reference})
    return operation


def _readback_connector_result(result: ReadbackResult, reference: str) -> ConnectorResult:
    terminal_ok = result.status in {ReadbackStatus.MATCHED, ReadbackStatus.SUCCEEDED}
    unknown = result.status in {
        ReadbackStatus.UNKNOWN,
        ReadbackStatus.UNAVAILABLE,
        ReadbackStatus.PENDING,
        ReadbackStatus.RUNNING,
        ReadbackStatus.ACCEPTED,
        ReadbackStatus.PARTIAL,
    }
    error = None
    if not terminal_ok:
        error = ConnectorError(
            ProviderErrorCode.REMOTE_STATE_UNKNOWN if unknown else ProviderErrorCode.PROVIDER_REFERENCE_MISMATCH,
            result.safe_error_code or result.status.value,
            retryable=bool(result.retryable),
        )
    return ConnectorResult(
        ok=terminal_ok,
        status=result.status.value,
        data=dict(result.evidence),
        provider_reference=result.provider_operation_id or reference,
        provider_status=result.status.value,
        retry_hint={
            "retryable": result.retryable,
            "retry_after_seconds": result.retry_after_seconds,
        },
        reconciliation_required=unknown,
        error=error,
    )


def execution_context(
    *,
    command: CommandEnvelope,
    adapter_context: AdapterContext,
    effect_class: EffectClass,
    effects_allowed: bool,
    operation: CommandOperation | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        tenant_id=command.tenant_id,
        environment=adapter_context.environment,
        correlation_id=command.correlation_id,
        actor_id=command.requested_by,
        command_id=str(command.command_id),
        causation_id=command.correlation_id,
        operation=command.command_type,
        connector_id=command.target,
        attempt=adapter_context.attempt,
        timeout_seconds=adapter_context.timeout_seconds,
        effect_class=effect_class,
        idempotency_key=command.idempotency_key,
        effects_allowed=effects_allowed,
        operation_snapshot=(
            operation.model_dump(mode="json") if operation is not None else {}
        ),
        payload=dict(adapter_context.payload),
        http=adapter_context.http,
    )


def connector_result_to_adapter(result: ConnectorResult) -> AdapterResult:
    if result.ok:
        outcome = Outcome.COMPLETED if result.status == "COMPLETED" else Outcome.ACCEPTED
        return AdapterResult(
            outcome,
            provider_operation_id=result.provider_reference,
            safe_details=dict(result.data),
        )
    if result.reconciliation_required:
        outcome = Outcome.UNKNOWN
        klass = ErrorClass.AMBIGUOUS
    elif result.error and result.error.retryable:
        outcome = Outcome.TRANSIENT
        klass = ErrorClass.RETRYABLE_BEFORE_EFFECT
    elif result.error and str(result.error.code) == ProviderErrorCode.CAPABILITY_UNSUPPORTED.value:
        outcome = Outcome.UNSUPPORTED
        klass = ErrorClass.UNSUPPORTED
    else:
        outcome = Outcome.REJECTED
        klass = ErrorClass.NON_RETRYABLE
    return AdapterResult(
        outcome,
        provider_operation_id=result.provider_reference,
        error_class=klass,
        safe_error_code=str(result.error.code) if result.error else result.status,
        safe_details=dict(result.data),
    )


def connector_result_to_readback(result: ConnectorResult) -> ReadbackResult:
    try:
        status = ReadbackStatus(result.provider_status or result.status)
    except ValueError:
        status = ReadbackStatus.UNKNOWN
    retry = result.retry_hint.get("retryable") if isinstance(result.retry_hint, Mapping) else None
    retry_after = result.retry_hint.get("retry_after_seconds") if isinstance(result.retry_hint, Mapping) else None
    return ReadbackResult(
        status=status,
        provider_operation_id=result.provider_reference,
        evidence=dict(result.data),
        safe_error_code=str(result.error.code) if result.error else None,
        retryable=retry if isinstance(retry, bool) else None,
        retry_after_seconds=float(retry_after) if isinstance(retry_after, (int, float)) else None,
    )
