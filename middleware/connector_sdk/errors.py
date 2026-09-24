"""Typed exceptions for the Codestra Connector SDK."""

from __future__ import annotations

from collections.abc import Iterable


class ConnectorError(RuntimeError):
    """Base error for connector registration and execution."""


class ManifestValidationError(ConnectorError):
    """Raised when a connector manifest violates the v1 contract."""

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(str(error) for error in errors)
        super().__init__("; ".join(self.errors) or "connector manifest is invalid")


class ConnectorNotFoundError(ConnectorError):
    """Raised when a connector identifier is not registered."""


class ConnectorVersionConflictError(ConnectorError):
    """Raised when connector version or immutable manifest identity conflicts."""


class ConnectorStateError(ConnectorError):
    """Raised when an operation is incompatible with connector state."""


class CommandNotAllowedError(ConnectorError):
    """Raised when no connector command policy authorizes a command."""


class CapabilityDisabledError(ConnectorError):
    """Raised when an externally effective capability is disabled."""


class WebhookVerificationError(ConnectorError):
    """Raised when a webhook fails source authentication or policy checks."""


class ReplayDetectedError(WebhookVerificationError):
    """Legacy exact-replay exception. Exact replays are normally acknowledged."""


class TenantResolutionError(WebhookVerificationError):
    """Raised when a verified provider identity cannot map to one tenant."""


class UnknownOutcomeError(ConnectorError):
    """Raised by an adapter when submission outcome cannot be established."""


class ReadBackRequiredError(ConnectorError):
    """Raised when authoritative destination read-back is incomplete."""


class StandardsValidationError(ConnectorError):
    """Raised when a standards-profile value is malformed."""
