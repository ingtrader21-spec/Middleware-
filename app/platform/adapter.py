"""The one provider adapter contract of the Middleware V3 kernel.

An adapter turns an accepted :class:`~app.commands.CommandEnvelope` into a
provider effect and normalises whatever the provider answers. The kernel
owns authentication, policy, safety, idempotency, retry, timeouts, breakers,
bulkheads, audit, correlation, secret references, metrics and kill switches;
the adapter receives them through :class:`AdapterContext` and must not
re-implement them.

Rules every adapter follows (enforced by the conformance suite):

* it never decides authorization, never reads the process environment,
  never opens a database pool or an HTTP client of its own (the shared
  ``httpx.AsyncClient`` arrives in the context);
* it never bypasses the kernel's safety decision and never writes into
  another adapter's state;
* an operation it does not support returns :attr:`Outcome.UNSUPPORTED` (or
  :attr:`ReadbackStatus.UNSUPPORTED`) explicitly — silence is never success;
* the only way to a ``COMPLETED`` operation is a ``MATCHED`` readback, so an
  adapter that claims completion still has to read the provider back.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Protocol, runtime_checkable

import httpx

from app.commands import CommandEnvelope, CommandOperation, redact_metadata
from app.secret_reference import SecretReference


class AdapterConfigurationError(ValueError):
    """The adapter cannot serve with the configuration it was given."""


class Outcome(StrEnum):
    """How one adapter attempt ended, from the kernel's point of view."""

    # The provider acknowledged the request; completion is decided by readback.
    ACCEPTED = "ACCEPTED"
    # The provider confirmed the effect in the same exchange; readback still
    # decides ``completed`` when the command registry requires it.
    COMPLETED = "COMPLETED"
    # Deterministic refusal before any effect could exist. Never retried blindly.
    REJECTED = "REJECTED"
    # Transport or provider failure *before* the request could be transmitted
    # (connection refused, DNS, 429/503 with a retry contract). Retryable.
    TRANSIENT = "TRANSIENT"
    # Timeout, reset or unparseable answer *after* transmission. The effect may
    # exist: the kernel quarantines the operation for reconciliation.
    UNKNOWN = "UNKNOWN"
    CANCELLED = "CANCELLED"
    UNSUPPORTED = "UNSUPPORTED"


class ReadbackStatus(StrEnum):
    MATCHED = "MATCHED"
    MISMATCH = "MISMATCH"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


class ErrorClass(StrEnum):
    RETRYABLE_BEFORE_EFFECT = "RETRYABLE_BEFORE_EFFECT"
    NON_RETRYABLE = "NON_RETRYABLE"
    AMBIGUOUS = "AMBIGUOUS"
    PROVIDER_AUTH = "PROVIDER_AUTH"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    UNSUPPORTED = "UNSUPPORTED"


SafeMapping = Mapping[str, str | int | float | bool | None]


@dataclass(frozen=True)
class AdapterContext:
    """Everything the kernel hands to an adapter for one attempt."""

    tenant_id: str
    command_id: str
    correlation_id: str
    attempt: int
    timeout_seconds: float
    environment: str
    deployment_sha: str
    http: httpx.AsyncClient | None = None
    secret_references: Mapping[str, SecretReference] = field(default_factory=dict)
    trace_context: Mapping[str, str] = field(default_factory=dict)
    test_syn: bool = False
    # The persisted command payload, for readback/reconcile/cancel (the
    # operation view carries no payload).
    payload: Mapping[str, Any] = field(default_factory=dict)

    def outbound_headers(self) -> dict[str, str]:
        """Correlation and trace propagation for every provider request."""
        headers = {"X-Correlation-ID": self.correlation_id}
        for name in ("traceparent", "tracestate"):
            value = self.trace_context.get(name)
            if isinstance(value, str) and value:
                headers[name] = value
        return headers


@dataclass(frozen=True)
class AdapterResult:
    """The normalised outcome of one attempt.

    ``provider_operation_id`` is an opaque, secret-free handle (message id,
    job id). ``safe_details`` is a bounded mapping the ledger may store; the
    kernel redacts it again before persistence.
    """

    outcome: Outcome
    provider_operation_id: str | None = None
    error_class: ErrorClass | None = None
    safe_error_code: str | None = None
    safe_details: SafeMapping = field(default_factory=dict)

    @property
    def acknowledged(self) -> bool:
        return self.outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}


@dataclass(frozen=True)
class ReadbackResult:
    """The provider state observed for an operation."""

    status: ReadbackStatus
    provider_operation_id: str | None = None
    evidence: SafeMapping = field(default_factory=dict)
    safe_error_code: str | None = None


@dataclass(frozen=True)
class AdapterReadiness:
    ready: bool
    detail: str = ""


@dataclass(frozen=True)
class AdapterCapabilities:
    """What an adapter advertises to the registry.

    ``connector_ids`` are the command-registry connector ids (the command
    ``target``) this adapter executes; ``capabilities`` the registry
    capability names it implements. ``safe_reexecution`` is the adapter's own
    statement that a deliberate second effect is safe to issue (REEXECUTE).
    """

    adapter_id: str
    version: str
    provider_family: str
    connector_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    supports_readback: bool = True
    supports_cancel: bool = False
    supports_status: bool = True
    safe_reexecution: bool = False
    external_effect: bool = True


@runtime_checkable
class Adapter(Protocol):
    """Mandatory surface. Everything is invoked only by the kernel."""

    adapter_id: str

    def validate_config(self) -> None: ...

    def capabilities(self) -> AdapterCapabilities: ...

    async def readiness(self, context: AdapterContext) -> AdapterReadiness: ...

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult: ...

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult: ...

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult: ...

    async def reconcile(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult: ...

    async def cancel(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult: ...

    def normalize_result(self, raw: Any) -> AdapterResult: ...

    def classify_error(self, error: BaseException) -> ErrorClass: ...

    def redact(self, value: Any) -> Any: ...


ADAPTER_METHODS = (
    "validate_config",
    "capabilities",
    "readiness",
    "execute",
    "status",
    "readback",
    "reconcile",
    "cancel",
    "normalize_result",
    "classify_error",
    "redact",
)


def assert_adapter(candidate: object) -> Adapter:
    missing = [name for name in ADAPTER_METHODS if not callable(getattr(candidate, name, None))]
    adapter_id = getattr(candidate, "adapter_id", None)
    if not isinstance(adapter_id, str) or not adapter_id:
        missing.insert(0, "adapter_id")
    if missing:
        raise AdapterConfigurationError(
            f"{type(candidate).__name__} does not implement the adapter contract: missing {missing}"
        )
    return candidate  # type: ignore[return-value]


def classify_transport_error(error: BaseException) -> ErrorClass:
    """The kernel's default transport classification (adapters may refine it).

    Anything that fails *before* a request is transmitted is retryable; a
    timeout, reset or unexpected exception once bytes may have left the
    process is ambiguous (fail closed).
    """
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout)):
        return ErrorClass.RETRYABLE_BEFORE_EFFECT
    if isinstance(error, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError)):
        return ErrorClass.AMBIGUOUS
    if isinstance(error, httpx.TransportError):
        return ErrorClass.AMBIGUOUS
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return ErrorClass.AMBIGUOUS
    if isinstance(error, (AdapterConfigurationError, ValueError, TypeError, KeyError)):
        # Deterministic validation/programming errors: nothing was sent.
        return ErrorClass.NON_RETRYABLE
    # Anything else raised around a provider call is ambiguous by default:
    # the request may have left the process. Fail closed into reconciliation.
    return ErrorClass.AMBIGUOUS


def classify_status(status_code: int) -> Outcome:
    """Provider HTTP status → outcome, for adapters over HTTP providers."""
    if status_code in {200, 201, 204}:
        return Outcome.COMPLETED
    if status_code == 202:
        return Outcome.ACCEPTED
    if status_code in {408, 425, 429, 502, 503, 504}:
        return Outcome.TRANSIENT
    if 400 <= status_code < 500:
        return Outcome.REJECTED
    if status_code >= 500:
        # A 5xx after the request reached the provider is ambiguous: the
        # provider may have applied the effect before failing to answer.
        return Outcome.UNKNOWN
    return Outcome.UNKNOWN


class BaseAdapter:
    """Sensible defaults so an adapter only writes what differs.

    ``cancel`` and ``status`` are UNSUPPORTED unless overridden; ``redact``
    applies the kernel's metadata redaction; ``classify_error`` uses the
    transport classification.
    """

    adapter_id: str = ""
    version: str = "1.0.0"
    provider_family: str = ""
    connector_ids: tuple[str, ...] = ()
    served_capabilities: tuple[str, ...] = ()
    supports_readback: bool = True
    supports_cancel: bool = False
    supports_status: bool = False
    safe_reexecution: bool = False
    external_effect: bool = True

    def validate_config(self) -> None:
        if not self.adapter_id or not self.provider_family:
            raise AdapterConfigurationError("adapter needs an id and a provider family")
        if not self.connector_ids or not self.served_capabilities:
            raise AdapterConfigurationError(
                f"{self.adapter_id}: an adapter must own connector ids and capabilities"
            )

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            adapter_id=self.adapter_id,
            version=self.version,
            provider_family=self.provider_family,
            connector_ids=tuple(self.connector_ids),
            capabilities=tuple(self.served_capabilities),
            supports_readback=self.supports_readback,
            supports_cancel=self.supports_cancel,
            supports_status=self.supports_status,
            safe_reexecution=self.safe_reexecution,
            external_effect=self.external_effect,
        )

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        return AdapterReadiness(ready=True, detail="configured")

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="status_unsupported")

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        return ReadbackResult(ReadbackStatus.UNSUPPORTED, safe_error_code="readback_unsupported")

    async def reconcile(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        return await self.readback(operation, context)

    async def cancel(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="cancel_unsupported")

    def normalize_result(self, raw: Any) -> AdapterResult:
        if isinstance(raw, AdapterResult):
            return raw
        if isinstance(raw, Mapping):
            status_code = raw.get("status_code")
            if isinstance(status_code, int) and not isinstance(status_code, bool):
                outcome = classify_status(status_code)
                reference = raw.get("provider_operation_id") or raw.get("id")
                return AdapterResult(
                    outcome,
                    provider_operation_id=str(reference) if reference is not None else None,
                    error_class=(
                        None
                        if outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}
                        else ErrorClass.AMBIGUOUS
                        if outcome is Outcome.UNKNOWN
                        else ErrorClass.RETRYABLE_BEFORE_EFFECT
                        if outcome is Outcome.TRANSIENT
                        else ErrorClass.NON_RETRYABLE
                    ),
                    safe_error_code=None if outcome in {Outcome.ACCEPTED, Outcome.COMPLETED} else f"provider_http_{status_code}",
                )
        return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="unnormalizable_result")

    def classify_error(self, error: BaseException) -> ErrorClass:
        return classify_transport_error(error)

    def redact(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return redact_metadata(dict(value))
        return value
