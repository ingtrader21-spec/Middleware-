"""Codestra Connector SDK v1.

This package is framework-neutral. FastAPI, worker, and Temporal adapters can
bind these services without giving connector manifests the ability to load
code or contain secret values.
"""

from .catalog import ConnectorCatalogService
from .errors import (
    CapabilityDisabledError,
    CommandNotAllowedError,
    ConnectorError,
    ConnectorNotFoundError,
    ConnectorStateError,
    ConnectorVersionConflictError,
    ManifestValidationError,
    ReadBackRequiredError,
    ReplayDetectedError,
    StandardsValidationError,
    TenantResolutionError,
    UnknownOutcomeError,
    WebhookVerificationError,
)
from .interfaces import (
    AdapterFactory,
    CapabilityProvider,
    ConnectorAdapter,
    ReplayStore,
    SecretResolver,
    TenantResolver,
)
from .manifest import (
    canonical_manifest_json,
    load_manifest,
    manifest_digest,
    parse_manifest,
)
from .models import (
    CloudEventEnvelope,
    CommandContext,
    CommandOutcome,
    CommandRequest,
    CommandResult,
    ConnectionTestResult,
    ConnectorCell,
    ConnectorHealth,
    ConnectorManifest,
    ConnectorState,
    NormalizedWebhookEvent,
    ReplayDecision,
    VerifiedWebhook,
    WebhookProcessResult,
    WebhookRequest,
)
from .registry import ConnectorRegistry, RegisteredConnector
from .runtime import ConnectorRuntime, StaticCapabilityProvider
from .standards import (
    SemanticVersion,
    deep_freeze,
    deep_thaw,
    validate_rfc3339,
    validate_traceparent,
    validate_tracestate,
)
from .webhooks import (
    InMemoryReplayStore,
    MappingSecretResolver,
    MappingTenantResolver,
    WebhookProcessor,
)

__all__ = [
    "AdapterFactory",
    "CapabilityDisabledError",
    "CapabilityProvider",
    "CloudEventEnvelope",
    "CommandContext",
    "CommandNotAllowedError",
    "CommandOutcome",
    "CommandRequest",
    "CommandResult",
    "ConnectionTestResult",
    "ConnectorAdapter",
    "ConnectorCatalogService",
    "ConnectorCell",
    "ConnectorError",
    "ConnectorHealth",
    "ConnectorManifest",
    "ConnectorNotFoundError",
    "ConnectorRegistry",
    "ConnectorRuntime",
    "ConnectorState",
    "ConnectorStateError",
    "ConnectorVersionConflictError",
    "InMemoryReplayStore",
    "ManifestValidationError",
    "MappingSecretResolver",
    "MappingTenantResolver",
    "NormalizedWebhookEvent",
    "ReadBackRequiredError",
    "RegisteredConnector",
    "ReplayDecision",
    "ReplayDetectedError",
    "ReplayStore",
    "SecretResolver",
    "SemanticVersion",
    "StandardsValidationError",
    "StaticCapabilityProvider",
    "TenantResolutionError",
    "TenantResolver",
    "UnknownOutcomeError",
    "VerifiedWebhook",
    "WebhookProcessResult",
    "WebhookProcessor",
    "WebhookRequest",
    "WebhookVerificationError",
    "canonical_manifest_json",
    "deep_freeze",
    "deep_thaw",
    "load_manifest",
    "manifest_digest",
    "parse_manifest",
    "validate_rfc3339",
    "validate_traceparent",
    "validate_tracestate",
]
