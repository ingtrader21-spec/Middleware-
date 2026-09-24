"""Framework-neutral connector interfaces.

The manifest never names a Python module or class. Adapter factories must be
registered explicitly by trusted application code, preventing arbitrary code
loading from a connector manifest.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from .models import (
    CommandRequest,
    CommandResult,
    ConnectionTestResult,
    ConnectorHealth,
    ConnectorManifest,
    NormalizedWebhookEvent,
    ReplayDecision,
    VerifiedWebhook,
)


class SecretResolver(Protocol):
    def resolve(self, reference: str) -> bytes:
        """Return current secret bytes for a reviewed runtime reference."""

    def resolve_all(self, reference: str) -> Sequence[bytes]:
        """Return current and still-valid previous secret bytes."""


class ReplayStore(Protocol):
    def claim(
        self,
        event_key: str,
        body_sha256: str,
        ttl_seconds: int,
    ) -> ReplayDecision:
        """Atomically classify a new event, exact replay, or body conflict."""

    def is_completed(self, event_key: str, body_sha256: str) -> bool:
        """Return whether the exact delivery already completed normalization."""

    def complete(self, event_key: str, body_sha256: str) -> None:
        """Mark the claimed exact delivery as successfully normalized."""


class CapabilityProvider(Protocol):
    def is_enabled(self, tenant_id: str, capability: str) -> bool:
        """Return the authoritative effective capability state."""


class TenantResolver(Protocol):
    def resolve(
        self,
        connector_id: str,
        endpoint_key: str,
        external_account_reference: str,
    ) -> str:
        """Map a verified provider account reference to one authoritative tenant."""


class ConnectorAdapter(ABC):
    """Adapter contract implemented once per connected software product."""

    @abstractmethod
    def validate_configuration(
        self,
        manifest: ConnectorManifest,
        configuration: Mapping[str, Any],
    ) -> tuple[str, ...]:
        """Return safe validation errors without making external changes."""

    @abstractmethod
    def test_connection(
        self,
        manifest: ConnectorManifest,
        configuration: Mapping[str, Any],
    ) -> ConnectionTestResult:
        """Perform a read-only connectivity and identity test."""

    @abstractmethod
    def execute_command(self, request: CommandRequest) -> CommandResult:
        """Submit one idempotent, policy-approved connector command."""

    @abstractmethod
    def read_back(
        self,
        request: CommandRequest,
        prior_result: CommandResult,
    ) -> CommandResult:
        """Read authoritative destination state after submission."""

    @abstractmethod
    def normalize_webhook(
        self,
        webhook: VerifiedWebhook,
    ) -> NormalizedWebhookEvent:
        """Translate a verified provider callback into a canonical event."""

    @abstractmethod
    def reconcile_unknown(
        self,
        request: CommandRequest,
        prior_result: CommandResult,
    ) -> CommandResult:
        """Reconcile an unknown external outcome without blind resubmission."""

    @abstractmethod
    def health(self) -> ConnectorHealth:
        """Return redacted connector health."""

    def compensate(
        self,
        request: CommandRequest,
        prior_result: CommandResult,
    ) -> CommandResult:
        """Optional compensation hook. Default is a safe unsupported result."""
        return CommandResult(
            outcome=prior_result.outcome,
            operation_id=prior_result.operation_id,
            provider_reference=prior_result.provider_reference,
            safe_result={"compensation": "UNSUPPORTED"},
            retryable=False,
            error_code="COMPENSATION_UNSUPPORTED",
        )


AdapterFactory = Callable[[ConnectorManifest], ConnectorAdapter]
