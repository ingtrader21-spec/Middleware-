"""Regression coverage for the independent Connector SDK review findings."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
import unittest
import uuid
from pathlib import Path
from typing import Any

from middleware.connector_sdk import (
    ConnectorCatalogService,
    ConnectorNotFoundError,
    ConnectorRegistry,
    ConnectorState,
    ConnectorVersionConflictError,
    InMemoryReplayStore,
    MappingSecretResolver,
    MappingTenantResolver,
    NormalizedWebhookEvent,
    ReplayDecision,
    WebhookProcessResult,
    WebhookProcessor,
    WebhookRequest,
    WebhookVerificationError,
    manifest_digest,
)
from middleware.connector_sdk.errors import StandardsValidationError
from middleware.connector_sdk.standards import (
    validate_rfc3339,
    validate_traceparent,
)
from tests.test_connector_sdk_v1 import FakeAdapter

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "connectors" / "manifests"


def _activate(registry: ConnectorRegistry, connector_id: str) -> None:
    registry.set_state(
        connector_id,
        expected_state=ConnectorState.DECLARED,
        new_state=ConnectorState.VALIDATED,
    )
    registry.set_state(
        connector_id,
        expected_state=ConnectorState.VALIDATED,
        new_state=ConnectorState.INSTALLED_DISABLED,
    )
    registry.set_state(
        connector_id,
        expected_state=ConnectorState.INSTALLED_DISABLED,
        new_state=ConnectorState.ACTIVE,
    )


def _payload(
    tenant_id: str,
    *,
    event_type: str = "email.message.delivered.v1",
    account: str = "acct-review",
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "account_reference": account,
        "correlation_id": str(uuid.uuid4()),
        "causation_id": str(uuid.uuid4()),
        "occurred_at": "2026-08-27T21:00:00Z",
        "data": {"message_id": "review-message"},
    }


def _request(
    body: bytes,
    *,
    secret: bytes,
    now: int,
    event_id: str,
) -> WebhookRequest:
    signature = hmac.new(
        secret,
        str(now).encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    return WebhookRequest(
        headers={
            "Content-Type": "application/json",
            "X-Postal-Signature": "v1=" + signature,
            "X-Postal-Timestamp": str(now),
            "X-Postal-Event-Id": event_id,
        },
        body=body,
        received_at_epoch=now,
    )


class FailOnceAdapter(FakeAdapter):
    def __init__(self, manifest: Any) -> None:
        super().__init__(manifest)
        self.fail_next_normalization = True

    def normalize_webhook(self, webhook: Any) -> NormalizedWebhookEvent:
        if self.fail_next_normalization:
            self.fail_next_normalization = False
            raise RuntimeError("synthetic normalization failure")
        return super().normalize_webhook(webhook)


class ConnectorSdkReviewFindingTests(unittest.TestCase):
    @staticmethod
    def raw(connector_id: str) -> dict[str, Any]:
        return json.loads(
            (MANIFESTS / f"{connector_id}.connector.json").read_text()
        )

    def test_catalog_rejects_global_conflict_before_mutation(self) -> None:
        registry = ConnectorRegistry()
        registry.load_directory(MANIFESTS)
        candidate = copy.deepcopy(self.raw("klyrow-email"))
        candidate["connector_id"] = "duplicate-email"
        candidate["display_name"] = "Duplicate Email"
        candidate["repository"] = "appolon1908-hue/duplicate-email"
        service = ConnectorCatalogService(registry)

        with self.assertRaises(ConnectorVersionConflictError):
            service.install_disabled(
                candidate,
                expected_digest=manifest_digest(candidate),
            )
        with self.assertRaises(ConnectorNotFoundError):
            registry.get("duplicate-email")

    def test_trace_context_profile_rejects_future_versions(self) -> None:
        with self.assertRaises(StandardsValidationError):
            validate_traceparent(
                "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            )

    def test_rfc3339_grammar_is_checked_before_datetime_parsing(self) -> None:
        invalid = (
            "2026-08-27 21:00:00Z",
            "2026-08-27t21:00:00Z",
            "2026-8-27T21:00:00Z",
            "2026-08-27T21:00Z",
            "2026-08-27T21:00:00+0000",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(StandardsValidationError):
                    validate_rfc3339(value)
        self.assertEqual(
            validate_rfc3339("2026-08-27T21:00:00.123456Z"),
            "2026-08-27T21:00:00.123456Z",
        )

    def test_exact_replay_recovers_after_normalization_failure(self) -> None:
        registry = ConnectorRegistry()
        registry.load_directory(MANIFESTS)
        _activate(registry, "klyrow-email")
        adapter = FailOnceAdapter(registry.get("klyrow-email").manifest)
        registry.register_adapter_factory("klyrow-email", lambda _: adapter)

        tenant_id = str(uuid.uuid4())
        secret = b"r" * 32
        now = int(time.time())
        body = json.dumps(
            _payload(tenant_id),
            separators=(",", ":"),
        ).encode()
        request = _request(
            body,
            secret=secret,
            now=now,
            event_id="evt-recoverable",
        )
        processor = WebhookProcessor(
            registry,
            MappingSecretResolver({"WEBHOOK_POSTAL_HMAC_SECRET": secret}),
            InMemoryReplayStore(),
            MappingTenantResolver(
                {("klyrow-email", "postal-events", "acct-review"): tenant_id}
            ),
        )

        with self.assertRaisesRegex(RuntimeError, "normalization failure"):
            processor.process("klyrow-email", "postal-events", request)
        result = processor.process("klyrow-email", "postal-events", request)
        self.assertIsInstance(result, WebhookProcessResult)
        self.assertEqual(result.decision, ReplayDecision.EXACT_REPLAY)
        assert result.cloud_event is not None
        self.assertEqual(result.cloud_event.id, "evt-recoverable")

    def test_webhook_requires_declared_inbound_event_direction(self) -> None:
        raw = self.raw("klyrow-email")
        for event in raw["events"]:
            if event["event_type"] == "email.message.delivered.v1":
                event["direction"] = "outbound"
        registry = ConnectorRegistry()
        registry.register_manifest(raw)
        _activate(registry, "klyrow-email")
        registry.register_adapter_factory("klyrow-email", FakeAdapter)

        tenant_id = str(uuid.uuid4())
        secret = b"i" * 32
        now = int(time.time())
        body = json.dumps(
            _payload(tenant_id),
            separators=(",", ":"),
        ).encode()
        processor = WebhookProcessor(
            registry,
            MappingSecretResolver({"WEBHOOK_POSTAL_HMAC_SECRET": secret}),
            InMemoryReplayStore(),
            MappingTenantResolver(
                {("klyrow-email", "postal-events", "acct-review"): tenant_id}
            ),
        )
        with self.assertRaisesRegex(
            WebhookVerificationError,
            "undeclared inbound event type",
        ):
            processor.process(
                "klyrow-email",
                "postal-events",
                _request(
                    body,
                    secret=secret,
                    now=now,
                    event_id="evt-outbound-only",
                ),
            )

    def test_storage_contract_uses_tenant_composite_foreign_keys(self) -> None:
        sql = (
            ROOT / "contracts" / "connectors" / "connector-storage.v1.sql"
        ).read_text()
        required = (
            "UNIQUE (tenant_id, connection_id)",
            "FOREIGN KEY (tenant_id, connection_id)",
            "REFERENCES connector_sdk.connector_connections\n            (tenant_id, connection_id)",
            "UNIQUE (tenant_id, webhook_id)",
            "FOREIGN KEY (tenant_id, webhook_id)",
            "REFERENCES connector_sdk.connector_webhook_endpoints\n            (tenant_id, webhook_id)",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)


if __name__ == "__main__":
    unittest.main()
