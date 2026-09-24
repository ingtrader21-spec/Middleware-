"""Webhook source verification, replay protection, and CloudEvents normalization."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from .errors import (
    ConnectorStateError,
    StandardsValidationError,
    TenantResolutionError,
    WebhookVerificationError,
)
from .interfaces import ReplayStore, SecretResolver, TenantResolver
from .models import (
    CloudEventEnvelope,
    ConnectorState,
    ReplayDecision,
    VerifiedWebhook,
    WebhookProcessResult,
    WebhookRequest,
)
from .registry import ConnectorRegistry
from .standards import (
    SECRET_KEY_NAMES,
    forbidden_paths,
    validate_rfc3339,
    validate_traceparent,
    validate_tracestate,
    validate_uri_reference,
)

_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EXTERNAL_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")


class MappingSecretResolver:
    """Test/development resolver with support for secret-rotation overlap."""

    def __init__(
        self,
        values: Mapping[str, bytes | Sequence[bytes]],
    ) -> None:
        self._values = dict(values)

    def resolve_all(self, reference: str) -> tuple[bytes, ...]:
        try:
            raw = self._values[reference]
        except KeyError as error:
            raise WebhookVerificationError(
                f"secret reference is unavailable: {reference}"
            ) from error
        candidates = (raw,) if isinstance(raw, bytes) else tuple(raw)
        if not candidates:
            raise WebhookVerificationError(
                f"secret reference is empty: {reference}"
            )
        for value in candidates:
            if not isinstance(value, bytes) or len(value) < 32:
                raise WebhookVerificationError(
                    f"secret reference is invalid: {reference}"
                )
        return candidates

    def resolve(self, reference: str) -> bytes:
        return self.resolve_all(reference)[0]


class MappingTenantResolver:
    """Test/development authoritative provider-account-to-tenant mapping."""

    def __init__(
        self,
        values: Mapping[tuple[str, str, str], str],
    ) -> None:
        self._values = dict(values)

    def resolve(
        self,
        connector_id: str,
        endpoint_key: str,
        external_account_reference: str,
    ) -> str:
        try:
            tenant_id = self._values[
                (connector_id, endpoint_key, external_account_reference)
            ]
        except KeyError as error:
            raise TenantResolutionError(
                "verified provider account is not mapped to one tenant"
            ) from error
        try:
            return str(uuid.UUID(tenant_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise TenantResolutionError(
                "resolved tenant identity is invalid"
            ) from error


class InMemoryReplayStore:
    """Atomic TTL replay store for tests and local development only."""

    def __init__(self) -> None:
        self._claims: dict[str, tuple[str, int, bool]] = {}
        self._lock = threading.Lock()

    def claim(
        self,
        event_key: str,
        body_sha256: str,
        ttl_seconds: int,
    ) -> ReplayDecision:
        now = int(time.time())
        with self._lock:
            expired = [
                existing
                for existing, (_, expires_at, _) in self._claims.items()
                if expires_at <= now
            ]
            for existing in expired:
                self._claims.pop(existing, None)
            prior = self._claims.get(event_key)
            if prior is not None:
                prior_digest, _, _ = prior
                if prior_digest == body_sha256:
                    return ReplayDecision.EXACT_REPLAY
                return ReplayDecision.SEMANTIC_CONFLICT
            self._claims[event_key] = (
                body_sha256,
                now + ttl_seconds,
                False,
            )
            return ReplayDecision.NEW

    def is_completed(self, event_key: str, body_sha256: str) -> bool:
        with self._lock:
            prior = self._claims.get(event_key)
            return bool(
                prior is not None
                and prior[0] == body_sha256
                and prior[2]
            )

    def complete(self, event_key: str, body_sha256: str) -> None:
        with self._lock:
            prior = self._claims.get(event_key)
            if prior is None or prior[0] != body_sha256:
                raise WebhookVerificationError(
                    "webhook replay claim disappeared before completion"
                )
            self._claims[event_key] = (prior[0], prior[1], True)


def _case_insensitive_headers(
    headers: Mapping[str, str],
) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in normalized:
            raise WebhookVerificationError(
                f"duplicate webhook header: {key}"
            )
        normalized[lowered] = str(value)
    return normalized


def _signature_hex(raw: str) -> tuple[str, str]:
    value = raw.strip()
    version = "v1"
    if "=" in value:
        prefix, candidate = value.split("=", 1)
        if prefix != "v1":
            raise WebhookVerificationError(
                "unsupported webhook signature version"
            )
        value = candidate
    if len(value) != 64:
        raise WebhookVerificationError(
            "signature must be 32-byte SHA-256 hex"
        )
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise WebhookVerificationError(
            "signature is not hexadecimal"
        ) from error
    return version, value.lower()


def _secret_candidates(
    resolver: SecretResolver,
    reference: str,
) -> tuple[bytes, ...]:
    resolve_all = getattr(resolver, "resolve_all", None)
    if callable(resolve_all):
        values = tuple(resolve_all(reference))
    else:
        values = (resolver.resolve(reference),)
    if not values:
        raise WebhookVerificationError(
            f"secret reference is empty: {reference}"
        )
    for value in values:
        if not isinstance(value, bytes) or len(value) < 32:
            raise WebhookVerificationError(
                f"secret reference is invalid: {reference}"
            )
    return values


def _validate_content_type(headers: Mapping[str, str]) -> None:
    raw = headers.get("content-type")
    if raw is None:
        return
    media_type = raw.split(";", 1)[0].strip().lower()
    if not (
        media_type == "application/json"
        or media_type == "application/cloudevents+json"
        or media_type.endswith("+json")
    ):
        raise WebhookVerificationError(
            "webhook content type is not a supported JSON media type"
        )


class WebhookProcessor:
    def __init__(
        self,
        registry: ConnectorRegistry,
        secrets: SecretResolver,
        replay_store: ReplayStore,
        tenants: TenantResolver,
    ) -> None:
        self._registry = registry
        self._secrets = secrets
        self._replay_store = replay_store
        self._tenants = tenants

    def verify(
        self,
        connector_id: str,
        endpoint_key: str,
        request: WebhookRequest,
    ) -> VerifiedWebhook:
        record = self._registry.get(connector_id)
        if record.state is not ConnectorState.ACTIVE:
            raise ConnectorStateError(
                f"connector {connector_id} cannot accept webhooks in "
                f"{record.state.value}"
            )
        policy = record.manifest.webhook_policy_for(endpoint_key)
        if policy is None:
            raise WebhookVerificationError(
                f"unknown webhook endpoint: {connector_id}/{endpoint_key}"
            )
        if len(request.body) > policy.maximum_body_bytes:
            raise WebhookVerificationError(
                "webhook body exceeds policy limit"
            )

        headers = _case_insensitive_headers(request.headers)
        _validate_content_type(headers)
        try:
            signature_version, signature = _signature_hex(
                headers[policy.signature_header.lower()]
            )
            timestamp_raw = headers[policy.timestamp_header.lower()]
            event_id = headers[policy.event_id_header.lower()].strip()
        except KeyError as error:
            raise WebhookVerificationError(
                f"required webhook header is missing: {error.args[0]}"
            ) from error

        try:
            timestamp = int(timestamp_raw)
        except ValueError as error:
            raise WebhookVerificationError(
                "webhook timestamp must be Unix epoch seconds"
            ) from error
        if abs(request.received_at_epoch - timestamp) > (
            policy.maximum_clock_skew_seconds
        ):
            raise WebhookVerificationError(
                "webhook timestamp is outside policy"
            )
        if _EVENT_ID.fullmatch(event_id) is None:
            raise WebhookVerificationError("webhook event ID is invalid")

        signed = str(timestamp).encode("ascii") + b"." + request.body
        expected_values = [
            hmac.new(secret, signed, hashlib.sha256).hexdigest()
            for secret in _secret_candidates(
                self._secrets,
                policy.secret_reference,
            )
        ]
        verified = False
        for expected in expected_values:
            verified = hmac.compare_digest(expected, signature) or verified
        if not verified:
            raise WebhookVerificationError("webhook signature is invalid")

        body_digest = hashlib.sha256(request.body).hexdigest()
        replay_key = f"{connector_id}:{endpoint_key}:{event_id}"
        decision = self._replay_store.claim(
            replay_key,
            body_digest,
            policy.replay_retention_seconds,
        )
        if decision is ReplayDecision.SEMANTIC_CONFLICT:
            raise WebhookVerificationError(
                "webhook event ID was reused with a different body"
            )

        return VerifiedWebhook(
            connector_id=connector_id,
            endpoint_key=endpoint_key,
            event_id=event_id,
            body_sha256=body_digest,
            timestamp_epoch=timestamp,
            replay_key=replay_key,
            signature_version=signature_version,
            replay_decision=decision,
            body=request.body,
            headers=headers,
        )

    def process(
        self,
        connector_id: str,
        endpoint_key: str,
        request: WebhookRequest,
    ) -> WebhookProcessResult:
        verified = self.verify(connector_id, endpoint_key, request)
        record = self._registry.get(connector_id)
        adapter = self._registry.adapter_factory(connector_id)(record.manifest)

        # A successfully normalized delivery is idempotently acknowledged.
        # A delivery that was claimed but failed before completion is allowed
        # to retry with the same event ID and body digest.
        if (
            verified.replay_decision is ReplayDecision.EXACT_REPLAY
            and self._replay_store.is_completed(
                verified.replay_key,
                verified.body_sha256,
            )
        ):
            return WebhookProcessResult(
                decision=verified.replay_decision,
                verified=verified,
                cloud_event=None,
            )

        event = adapter.normalize_webhook(verified)
        if event.event_id != verified.event_id:
            raise WebhookVerificationError(
                "adapter changed the verified provider event ID"
            )
        if not any(
            policy.event_type == event.event_type
            and policy.direction == "inbound"
            for policy in record.manifest.event_policies
        ):
            raise WebhookVerificationError(
                "adapter emitted an undeclared inbound event type: "
                f"{event.event_type}"
            )
        if (
            _EXTERNAL_REFERENCE.fullmatch(event.external_account_reference)
            is None
        ):
            raise WebhookVerificationError(
                "adapter external account reference is invalid"
            )
        if not event.correlation_id or len(event.correlation_id) > 180:
            raise WebhookVerificationError(
                "normalized correlation ID is invalid"
            )
        if not event.causation_id or len(event.causation_id) > 180:
            raise WebhookVerificationError(
                "normalized causation ID is invalid"
            )
        try:
            validate_rfc3339(event.occurred_at)
            validate_traceparent(event.traceparent)
            validate_tracestate(event.tracestate)
        except StandardsValidationError as error:
            raise WebhookVerificationError(str(error)) from error

        secret_paths = forbidden_paths(event.payload, SECRET_KEY_NAMES)
        if secret_paths:
            raise WebhookVerificationError(
                "normalized event payload contains forbidden secret fields: "
                + ", ".join(secret_paths)
            )

        tenant_id = self._tenants.resolve(
            connector_id,
            endpoint_key,
            event.external_account_reference,
        )
        source = f"urn:codestra:connector:{connector_id}"
        validate_uri_reference(source, "CloudEvent source")
        extensions: dict[str, Any] = {
            "tenantid": tenant_id,
            "connectorid": connector_id,
            "endpointkey": endpoint_key,
            "correlationid": event.correlation_id,
            "causationid": event.causation_id,
        }
        if event.traceparent is not None:
            extensions["traceparent"] = event.traceparent
        if event.tracestate is not None:
            extensions["tracestate"] = event.tracestate

        cloud_event = CloudEventEnvelope(
            specversion="1.0",
            id=event.event_id,
            source=source,
            type=event.event_type,
            time=event.occurred_at,
            subject=event.subject or event.external_account_reference,
            datacontenttype="application/json",
            dataschema=(
                "https://contracts.codestra.co/events/"
                f"{event.event_type}.schema.json"
            ),
            data=event.payload,
            extensions=extensions,
        )
        self._replay_store.complete(
            verified.replay_key,
            verified.body_sha256,
        )
        return WebhookProcessResult(
            decision=verified.replay_decision,
            verified=verified,
            cloud_event=cloud_event,
        )
