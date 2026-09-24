"""Standards, security, and lifecycle regression tests for Connector SDK v1."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
import unittest
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from middleware.connector_sdk import (
    CapabilityDisabledError,
    CloudEventEnvelope,
    CommandContext,
    CommandNotAllowedError,
    CommandOutcome,
    CommandRequest,
    CommandResult,
    ConnectionTestResult,
    ConnectorAdapter,
    ConnectorCatalogService,
    ConnectorHealth,
    ConnectorManifest,
    ConnectorRegistry,
    ConnectorRuntime,
    ConnectorState,
    ConnectorStateError,
    ConnectorVersionConflictError,
    InMemoryReplayStore,
    ManifestValidationError,
    MappingSecretResolver,
    MappingTenantResolver,
    NormalizedWebhookEvent,
    ReadBackRequiredError,
    ReplayDecision,
    SemanticVersion,
    StaticCapabilityProvider,
    VerifiedWebhook,
    WebhookProcessor,
    WebhookRequest,
    WebhookVerificationError,
    manifest_digest,
    parse_manifest,
)
from middleware.connector_sdk.generation import build_generated_artifacts

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "connectors" / "manifests"


class FakeAdapter(ConnectorAdapter):
    result_outcome = CommandOutcome.SUBMITTED
    readback_outcome = CommandOutcome.COMPLETED
    leak_result = False
    change_operation_id = False

    def __init__(self, manifest: ConnectorManifest) -> None:
        self.manifest = manifest

    def validate_configuration(
        self,
        manifest: ConnectorManifest,
        configuration: Mapping[str, Any],
    ) -> tuple[str, ...]:
        del manifest
        return () if configuration.get("account_id") else (
            "account_id required",
        )

    def test_connection(
        self,
        manifest: ConnectorManifest,
        configuration: Mapping[str, Any],
    ) -> ConnectionTestResult:
        del manifest, configuration
        return ConnectionTestResult(
            ok=True,
            code="READ_ONLY_TEST_PASS",
        )

    def execute_command(
        self,
        request: CommandRequest,
    ) -> CommandResult:
        safe_result: dict[str, Any] = (
            {"access_token": "leak"}
            if self.leak_result
            else {"submitted": True}
        )
        return CommandResult(
            outcome=self.result_outcome,
            operation_id=request.command_id,
            safe_result=safe_result,
        )

    def read_back(
        self,
        request: CommandRequest,
        prior_result: CommandResult,
    ) -> CommandResult:
        operation_id = (
            str(uuid.uuid4())
            if self.change_operation_id
            else prior_result.operation_id
        )
        return CommandResult(
            outcome=self.readback_outcome,
            operation_id=operation_id,
            safe_result={"readback": "confirmed"},
        )

    def normalize_webhook(
        self,
        webhook: VerifiedWebhook,
    ) -> NormalizedWebhookEvent:
        payload = json.loads(webhook.body)
        return NormalizedWebhookEvent(
            event_id=webhook.event_id,
            event_type=payload["event_type"],
            external_account_reference=payload["account_reference"],
            correlation_id=payload["correlation_id"],
            causation_id=payload["causation_id"],
            occurred_at=payload["occurred_at"],
            payload=payload["data"],
            traceparent=payload.get("traceparent"),
        )

    def reconcile_unknown(
        self,
        request: CommandRequest,
        prior_result: CommandResult,
    ) -> CommandResult:
        return self.read_back(request, prior_result)

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            status="HEALTHY",
            checked_at_epoch=int(time.time()),
        )


class ConnectorSdkStandardsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ConnectorRegistry()
        self.records = self.registry.load_directory(MANIFESTS)

    @staticmethod
    def raw(connector_id: str) -> dict[str, Any]:
        return json.loads(
            (
                MANIFESTS / f"{connector_id}.connector.json"
            ).read_text()
        )

    def activate(
        self,
        connector_id: str,
        adapter: type[FakeAdapter] = FakeAdapter,
    ) -> None:
        self.registry.set_state(
            connector_id,
            expected_state=ConnectorState.DECLARED,
            new_state=ConnectorState.VALIDATED,
        )
        self.registry.set_state(
            connector_id,
            expected_state=ConnectorState.VALIDATED,
            new_state=ConnectorState.INSTALLED_DISABLED,
        )
        self.registry.set_state(
            connector_id,
            expected_state=ConnectorState.INSTALLED_DISABLED,
            new_state=ConnectorState.ACTIVE,
        )
        self.registry.register_adapter_factory(
            connector_id,
            adapter,
        )

    def request(self, tenant_id: str) -> CommandRequest:
        return CommandRequest(
            connector_id="klyrow-email",
            command_id=str(uuid.uuid4()),
            command_type="email.message.send.v1",
            command_version=1,
            payload={"message_id": "example"},
            context=CommandContext(
                tenant_id=tenant_id,
                actor_id="n8n-core-automation",
                correlation_id=str(uuid.uuid4()),
                causation_id=str(uuid.uuid4()),
                idempotency_key="email:test:0001",
                capability_snapshot={"EMAIL_DELIVERY": True},
                traceparent=(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-"
                    "00f067aa0ba902b7-01"
                ),
            ),
        )

    def webhook_request(
        self,
        *,
        secret: bytes,
        event_id: str = "evt-1",
        account_reference: str = "postal-server-1",
        body_suffix: bytes = b"",
        signature_secret: bytes | None = None,
        provider_tenant_id: str | None = None,
    ) -> tuple[WebhookRequest, str, dict[str, Any]]:
        now = int(time.time())
        payload = {
            "event_type": "email.message.delivered.v1",
            "account_reference": account_reference,
            "correlation_id": str(uuid.uuid4()),
            "causation_id": str(uuid.uuid4()),
            "occurred_at": "2026-08-27T21:00:00Z",
            "data": {"message_id": "m-1"},
        }
        if provider_tenant_id is not None:
            payload["tenant_id"] = provider_tenant_id
        body = (
            json.dumps(payload, separators=(",", ":")).encode()
            + body_suffix
        )
        used_secret = signature_secret or secret
        signature = hmac.new(
            used_secret,
            str(now).encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        request = WebhookRequest(
            headers={
                "Content-Type": "application/json",
                "X-Postal-Signature": "v1=" + signature,
                "X-Postal-Timestamp": str(now),
                "X-Postal-Event-Id": event_id,
            },
            body=body,
            received_at_epoch=now,
        )
        return request, account_reference, payload

    def processor(
        self,
        secret_values: bytes | tuple[bytes, ...],
        account_reference: str,
        tenant_id: str,
        replay_store: InMemoryReplayStore | None = None,
    ) -> WebhookProcessor:
        webhook_policy = (
            self.registry.get("klyrow-email")
            .manifest.webhook_policy_for("postal-events")
        )
        assert webhook_policy is not None
        return WebhookProcessor(
            self.registry,
            MappingSecretResolver(
                {webhook_policy.secret_reference: secret_values}
            ),
            replay_store or InMemoryReplayStore(),
            MappingTenantResolver(
                {
                    (
                        "klyrow-email",
                        "postal-events",
                        account_reference,
                    ): tenant_id
                }
            ),
        )

    def test_manifests_are_disabled_and_non_overlapping(self) -> None:
        self.assertEqual(
            {record.manifest.connector_id for record in self.records},
            {
                "ai-provider",
                "beyvra-nonfinancial",
                "klyrow-alert-email",
                "klyrow-email",
                "kyqra-crawler",
                "marketing-provider",
                "odoo-19",
                "postly-social",
                "provisioning-service",
                "telnexa-sms",
                "vicidial-restricted",
            },
        )
        self.assertEqual(
            self.registry.validate_global_invariants(),
            (),
        )
        for record in self.records:
            self.assertFalse(record.manifest.enabled_by_default)
            self.assertFalse(record.manifest.direct_n8n_access)
            self.assertTrue(
                record.manifest.runtime_binding.base_url.endswith(
                    ".invalid"
                )
            )

    def test_semver_200_precedence(self) -> None:
        self.assertLess(
            SemanticVersion.parse("1.0.0-alpha.2"),
            SemanticVersion.parse("1.0.0-alpha.10"),
        )
        self.assertLess(
            SemanticVersion.parse("1.0.0-rc.1"),
            SemanticVersion.parse("1.0.0"),
        )
        self.assertEqual(
            SemanticVersion.parse("1.0.0+build.1"),
            SemanticVersion.parse("1.0.0+build.2"),
        )

    def test_same_version_different_digest_is_rejected(self) -> None:
        registry = ConnectorRegistry()
        raw = self.raw("klyrow-email")
        registry.register_manifest(raw)
        changed = copy.deepcopy(raw)
        changed["display_name"] = "Changed"
        with self.assertRaises(ConnectorVersionConflictError):
            registry.register_manifest(changed, replace=True)

    def test_manifest_digest_is_stable_and_install_disabled(self) -> None:
        raw = self.raw("postly-social")
        digest = manifest_digest(raw)
        self.assertEqual(
            digest,
            manifest_digest(copy.deepcopy(raw)),
        )
        service = ConnectorCatalogService(ConnectorRegistry())
        projection = service.install_disabled(
            raw,
            expected_digest=digest,
        )
        self.assertEqual(
            projection["state"],
            "INSTALLED_DISABLED",
        )

    def test_state_machine_rejects_direct_activation(self) -> None:
        with self.assertRaises(ConnectorStateError):
            self.registry.set_state(
                "klyrow-email",
                expected_state=ConnectorState.DECLARED,
                new_state=ConnectorState.ACTIVE,
            )

    def test_registration_cannot_create_active_connector(self) -> None:
        registry = ConnectorRegistry()
        with self.assertRaises(ConnectorStateError):
            registry.register_manifest(
                self.raw("klyrow-email"),
                state=ConnectorState.ACTIVE,
            )

    def test_models_are_deeply_immutable(self) -> None:
        metadata = {"nested": {"value": 1}}
        raw = self.raw("klyrow-email")
        raw["metadata"] = metadata
        parsed = parse_manifest(raw)
        metadata["nested"]["value"] = 9
        self.assertEqual(
            parsed.metadata["nested"]["value"],
            1,
        )
        with self.assertRaises(TypeError):
            parsed.metadata["nested"]["value"] = 2

    def test_manifest_rejects_secrets_and_encoded_paths(self) -> None:
        raw = self.raw("klyrow-email")
        raw["metadata"]["api_key"] = "forbidden"
        with self.assertRaises(ManifestValidationError):
            parse_manifest(raw)
        raw = self.raw("klyrow-email")
        raw["runtime_binding"]["health_path"] = (
            "/health/%252e%252e/admin"
        )
        with self.assertRaises(ManifestValidationError):
            parse_manifest(raw)

    def test_manifest_rejects_duplicate_security_headers(self) -> None:
        raw = self.raw("klyrow-email")
        raw["webhooks"][0]["timestamp_header"] = (
            raw["webhooks"][0]["signature_header"].lower()
        )
        with self.assertRaises(ManifestValidationError):
            parse_manifest(raw)

    def test_runtime_fails_closed_and_requires_terminal_readback(self) -> None:
        self.activate("klyrow-email")
        tenant_id = str(uuid.uuid4())
        request = self.request(tenant_id)
        with self.assertRaises(CapabilityDisabledError):
            ConnectorRuntime(
                self.registry,
                StaticCapabilityProvider({}),
            ).execute(request)
        result = ConnectorRuntime(
            self.registry,
            StaticCapabilityProvider(
                {(tenant_id, "EMAIL_DELIVERY"): True}
            ),
        ).execute(request)
        self.assertEqual(
            result.outcome,
            CommandOutcome.COMPLETED,
        )

    def test_runtime_rejects_nonterminal_readback(self) -> None:
        class NonTerminalAdapter(FakeAdapter):
            readback_outcome = CommandOutcome.SUBMITTED

        self.activate("klyrow-email", NonTerminalAdapter)
        tenant_id = str(uuid.uuid4())
        with self.assertRaises(ReadBackRequiredError):
            ConnectorRuntime(
                self.registry,
                StaticCapabilityProvider(
                    {(tenant_id, "EMAIL_DELIVERY"): True}
                ),
            ).execute(self.request(tenant_id))

    def test_runtime_rejects_operation_id_switch(self) -> None:
        class SwitchingAdapter(FakeAdapter):
            change_operation_id = True

        self.activate("klyrow-email", SwitchingAdapter)
        tenant_id = str(uuid.uuid4())
        with self.assertRaises(CommandNotAllowedError):
            ConnectorRuntime(
                self.registry,
                StaticCapabilityProvider(
                    {(tenant_id, "EMAIL_DELIVERY"): True}
                ),
            ).execute(self.request(tenant_id))

    def test_runtime_rejects_result_secret_leak(self) -> None:
        class LeakingAdapter(FakeAdapter):
            leak_result = True

        self.activate("klyrow-email", LeakingAdapter)
        tenant_id = str(uuid.uuid4())
        with self.assertRaises(CommandNotAllowedError):
            ConnectorRuntime(
                self.registry,
                StaticCapabilityProvider(
                    {(tenant_id, "EMAIL_DELIVERY"): True}
                ),
            ).execute(self.request(tenant_id))

    def test_runtime_rejects_invalid_trace_context(self) -> None:
        self.activate("klyrow-email")
        tenant_id = str(uuid.uuid4())
        request = self.request(tenant_id)
        invalid = CommandRequest(
            connector_id=request.connector_id,
            command_id=request.command_id,
            command_type=request.command_type,
            command_version=request.command_version,
            payload=request.payload,
            context=CommandContext(
                tenant_id=request.context.tenant_id,
                actor_id=request.context.actor_id,
                correlation_id=request.context.correlation_id,
                causation_id=request.context.causation_id,
                idempotency_key=request.context.idempotency_key,
                capability_snapshot=request.context.capability_snapshot,
                traceparent="00-" + "0" * 32 + "-" + "0" * 16 + "-00",
            ),
        )
        with self.assertRaises(CommandNotAllowedError):
            ConnectorRuntime(
                self.registry,
                StaticCapabilityProvider(
                    {(tenant_id, "EMAIL_DELIVERY"): True}
                ),
            ).execute(invalid)

    def test_webhook_new_event_becomes_cloudevent_10(self) -> None:
        self.activate("klyrow-email")
        secret = b"x" * 32
        tenant_id = str(uuid.uuid4())
        request, account, _ = self.webhook_request(secret=secret)
        result = self.processor(
            secret,
            account,
            tenant_id,
        ).process(
            "klyrow-email",
            "postal-events",
            request,
        )
        self.assertEqual(result.decision, ReplayDecision.NEW)
        self.assertIsInstance(
            result.cloud_event,
            CloudEventEnvelope,
        )
        assert result.cloud_event is not None
        event = result.cloud_event.as_dict()
        self.assertEqual(event["specversion"], "1.0")
        self.assertEqual(event["tenantid"], tenant_id)
        self.assertEqual(
            event["source"],
            "urn:codestra:connector:klyrow-email",
        )

    def test_exact_webhook_replay_is_idempotently_acknowledgeable(self) -> None:
        self.activate("klyrow-email")
        secret = b"x" * 32
        tenant_id = str(uuid.uuid4())
        request, account, _ = self.webhook_request(secret=secret)
        replay_store = InMemoryReplayStore()
        processor = self.processor(
            secret,
            account,
            tenant_id,
            replay_store,
        )
        first = processor.process(
            "klyrow-email",
            "postal-events",
            request,
        )
        second = processor.process(
            "klyrow-email",
            "postal-events",
            request,
        )
        self.assertEqual(first.decision, ReplayDecision.NEW)
        self.assertEqual(
            second.decision,
            ReplayDecision.EXACT_REPLAY,
        )
        self.assertIsNone(second.cloud_event)

    def test_webhook_event_id_body_conflict_is_rejected(self) -> None:
        self.activate("klyrow-email")
        secret = b"y" * 32
        tenant_id = str(uuid.uuid4())
        first, account, _ = self.webhook_request(
            secret=secret,
            event_id="evt-conflict",
        )
        replay_store = InMemoryReplayStore()
        processor = self.processor(
            secret,
            account,
            tenant_id,
            replay_store,
        )
        processor.process(
            "klyrow-email",
            "postal-events",
            first,
        )
        second, _, _ = self.webhook_request(
            secret=secret,
            event_id="evt-conflict",
            account_reference=account,
            body_suffix=b" ",
        )
        with self.assertRaises(WebhookVerificationError):
            processor.process(
                "klyrow-email",
                "postal-events",
                second,
            )

    def test_webhook_secret_rotation_overlap(self) -> None:
        self.activate("klyrow-email")
        current = b"c" * 32
        previous = b"p" * 32
        tenant_id = str(uuid.uuid4())
        request, account, _ = self.webhook_request(
            secret=current,
            signature_secret=previous,
        )
        result = self.processor(
            (current, previous),
            account,
            tenant_id,
        ).process(
            "klyrow-email",
            "postal-events",
            request,
        )
        self.assertEqual(result.decision, ReplayDecision.NEW)

    def test_webhook_tenant_is_not_trusted_from_payload(self) -> None:
        self.activate("klyrow-email")
        secret = b"z" * 32
        authoritative_tenant = str(uuid.uuid4())
        request, account, _ = self.webhook_request(
            secret=secret,
            provider_tenant_id=str(uuid.uuid4()),
        )
        result = self.processor(
            secret,
            account,
            authoritative_tenant,
        ).process(
            "klyrow-email",
            "postal-events",
            request,
        )
        assert result.cloud_event is not None
        self.assertEqual(
            result.cloud_event.as_dict()["tenantid"],
            authoritative_tenant,
        )

    def test_scaffolder_output_remains_disabled_and_valid(self) -> None:
        from scripts.scaffold_connector import build_manifest

        from argparse import Namespace

        class Args(Namespace):
            connector_id = "sample-api"
            display_name = "Sample API"
            repository = "appolon1908-hue/sample-api"
            cell = "core-communications"
            command_prefix = "sample."
            capability = "SAMPLE_WRITE"
            workflow_family = "product.sample-api"
            event_type = "sample.record.changed.v1"
            webhook_endpoint_key = "provider-events"

        manifest = parse_manifest(build_manifest(Args()))
        self.assertFalse(manifest.enabled_by_default)
        self.assertFalse(manifest.direct_n8n_access)

    def test_generated_artifacts_match_manifests(self) -> None:
        artifacts = build_generated_artifacts(MANIFESTS)
        self.assertEqual(
            set(artifacts),
            {
                "kong-routes.v1.json",
                "keycloak-clients.v1.json",
                "n8n-workflow-packs.v1.json",
                "command-registry.v1.json",
            },
        )
        self.assertEqual(
            len(artifacts["kong-routes.v1.json"]["routes"]),
            8,
        )


if __name__ == "__main__":
    unittest.main()
