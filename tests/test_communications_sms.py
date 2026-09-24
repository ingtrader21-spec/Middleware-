from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import UUID, uuid4

import jwt
from fastapi.testclient import TestClient

from app.commands import (
    CommandEnvelope,
    CommandState,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    MemoryCommandStore,
)
from app.communications import CommunicationsService, MemoryCommunicationsStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError, AuthorizationError
from app.sms import sms_segments
from app.storage import MemoryInboxStore


def _token(client_id: str, scopes: list[str], *, tenant_id: str = "tenant-1") -> str:
    return jwt.encode(
        {
            "azp": client_id,
            "scope": " ".join(scopes),
            "aud": "middleware-api",
            "tenant_id": tenant_id,
            "sub": "user-123",
            "iss": "https://auth.codestra.co/realms/codestra",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300,
            "jti": str(uuid4()),
        },
        "test-only-key",
        algorithm="HS256",
    )


class ProductTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("Authorization must be a Bearer token")
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        if claims.get("azp") != expected_client_id:
            raise AuthorizationError("token azp does not match producer")
        if required_scope not in set(str(claims.get("scope") or "").split()):
            raise AuthorizationError("required scope is missing")
        return claims

    async def ready(self) -> bool:
        return True


class CapturingCommandStore(MemoryCommandStore):
    def __init__(self) -> None:
        super().__init__()
        self.submitted: list[CommandEnvelope] = []
        self.authenticated_client_ids: list[str] = []

    async def submit(
        self,
        command: CommandEnvelope,
        *,
        authenticated_client_id: str,
        **kernel_kwargs,
    ):
        self.submitted.append(command.model_copy(deep=True))
        self.authenticated_client_ids.append(authenticated_client_id)
        return await super().submit(
            command,
            authenticated_client_id=authenticated_client_id,
            **kernel_kwargs,
        )


def _runtime(test_settings, *, sms_enabled: bool = True) -> Runtime:
    command_store = CapturingCommandStore()
    commands = CommandService(
        command_store,
        CommandPolicyRegistry(
            (
                CommandPolicy(
                    prefix="sms.",
                    target="telnexa-sms",
                    capability="SMS_DELIVERY",
                    readback_required=True,
                ),
            ),
            {"SMS_DELIVERY": sms_enabled},
        ),
    )
    store = MemoryCommunicationsStore()
    store.verified_senders.add(("tenant-1", "Telnexa"))
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=ProductTokenVerifier(),
        commands=commands,
        communications=CommunicationsService(store=store, commands=commands),
    )


def _headers(
    *,
    scope: str = "kyqra.middleware.command.write",
    tenant: str = "tenant-1",
    key: str = "sms-key-0001",
) -> dict[str, str]:
    return {
        "Authorization": "Bearer " + _token("kyqra", [scope], tenant_id=tenant),
        "X-Tenant-ID": tenant,
        "X-Correlation-ID": "sms-correlation-1",
        "Idempotency-Key": key,
    }


def _message(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "channel": "sms",
        "from": "Telnexa",
        "to": ["+49123456789"],
        "content": {"text": "Safe SMS message"},
        "metadata": {
            "category": "transactional",
            "consent": "granted",
            "billingAccountId": "00000000-0000-4000-8000-000000000010",
        },
    }
    value.update(updates)
    return value


def _event(
    *,
    event_type: str,
    payload: dict[str, Any],
    event_id: str | None = None,
) -> dict[str, Any]:
    identity = event_id or str(uuid4())
    return {
        "event_id": identity,
        "event_type": event_type,
        "event_version": "1.0",
        "occurred_at": "2026-08-30T12:00:00Z",
        "received_at": "2026-08-30T12:00:01Z",
        "source": "telnexa-gateway",
        "tenant_id": "tenant-1",
        "correlation_id": "sms-correlation-1",
        "causation_id": "sms-provider-event",
        "idempotency_key": identity,
        "payload": payload,
        "metadata": {},
    }


def _sign(event: dict[str, Any]) -> dict[str, str]:
    path = "/api/v1/telnexa/events"
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    canonical = "\n".join(
        (
            "v1",
            "POST",
            path,
            timestamp,
            event["event_id"],
            "telnexa-gateway",
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()
    signature = hmac.new(
        b"test-secret-value-that-is-at-least-thirty-two-bytes",
        canonical,
        hashlib.sha256,
    ).hexdigest()
    return {
        "Authorization": "Bearer "
        + _token("telnexa-gateway", ["sms.events.publish"]),
        "Content-Type": "application/json",
        "Idempotency-Key": event["event_id"],
        "X-Codestra-Event-Id": event["event_id"],
        "X-Codestra-Event-Type": event["event_type"],
        "X-Codestra-Source": "telnexa-gateway",
        "X-Codestra-Tenant-Id": event["tenant_id"],
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Signature": "sha256=" + signature,
        "X-Correlation-Id": event["correlation_id"],
    }


def _post_event(client: TestClient, event: dict[str, Any]):
    return client.post(
        "/api/v1/telnexa/events",
        content=json.dumps(event, separators=(",", ":"), sort_keys=True),
        headers=_sign(event),
    )


def test_sms_api_creates_one_canonical_telnexa_command_and_usage(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        first = client.post(
            "/v1/communications/messages",
            json=_message(content={"text": "Hello ^ world"}),
            headers=_headers(),
        )
        assert first.status_code == 202, first.text
        message = first.json()
        assert message["channel"] == "sms"
        assert message["status"] == "queued"
        assert message["provider"] == "telnexa"
        assert message["metadata"]["encoding"] == "GSM-7"
        assert message["metadata"]["segments"] == 1

        replay = client.post(
            "/v1/communications/messages",
            json=_message(content={"text": "Hello ^ world"}),
            headers=_headers(),
        )
        assert replay.status_code == 200
        assert replay.json()["messageId"] == message["messageId"]
        conflict = client.post(
            "/v1/communications/messages",
            json=_message(content={"text": "changed"}),
            headers=_headers(),
        )
        assert conflict.status_code == 409

        assert runtime.commands is not None

        assert isinstance(runtime.commands.store, CapturingCommandStore)
        assert len(runtime.commands.store.submitted) == 1
        assert runtime.commands.store.authenticated_client_ids == ["kyqra"]
        command = runtime.commands.store.submitted[0]
        assert command.command_type == "sms.message.submit.v1"
        assert command.target == "telnexa-sms"
        assert command.capability == "SMS_DELIVERY"
        assert command.payload["destination"] == "+49123456789"
        assert command.payload["sender"] == "Telnexa"
        assert command.payload["encoding"] == "GSM-7"
        assert command.payload["segments"] == 1
        assert not set(command.payload) & {
            "password",
            "client_secret",
            "provider_token",
        }

        usage = client.get(
            "/v1/communications/usage",
            headers=_headers(scope="kyqra.middleware.status.read"),
        )
        assert usage.status_code == 200
        totals = {item["channel"]: item for item in usage.json()["totals"]}
        assert totals["sms"]["accepted"] == 1
        assert totals["email"]["accepted"] == 0
        naive_usage = client.get(
            "/v1/communications/usage?from=2026-09-01T12:00:00",
            headers=_headers(scope="kyqra.middleware.status.read"),
        )
        assert naive_usage.status_code == 400
        assert naive_usage.json()["error"]["code"] == "invalid_request"


def test_sms_schema_sender_scope_and_kill_switch_fail_closed(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        invalid_phone = client.post(
            "/v1/communications/messages",
            json=_message(to=["49123456789"]),
            headers=_headers(key="sms-invalid-phone"),
        )
        assert invalid_phone.status_code == 400
        multiple = client.post(
            "/v1/communications/messages",
            json=_message(to=["+49123456789", "+49123456780"]),
            headers=_headers(key="sms-multiple"),
        )
        assert multiple.status_code == 400
        html = client.post(
            "/v1/communications/messages",
            json=_message(content={"text": "hello", "html": "<b>hello</b>"}),
            headers=_headers(key="sms-html"),
        )
        assert html.status_code == 400
        wrong_scope = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(
                scope="kyqra.middleware.status.read",
                key="sms-wrong-scope",
            ),
        )
        assert wrong_scope.status_code == 403
        unverified = client.post(
            "/v1/communications/messages",
            json=_message(**{"from": "Other"}),
            headers=_headers(key="sms-unverified"),
        )
        assert unverified.status_code == 400
        short_idempotency = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="short"),
        )
        assert short_idempotency.status_code == 400

    disabled = _runtime(test_settings, sms_enabled=False)
    disabled_app = create_app(settings=test_settings, runtime=disabled)
    with TestClient(disabled_app) as client:
        blocked = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="sms-disabled"),
        )
        assert blocked.status_code == 403
    assert disabled.communications is not None
    assert disabled.communications.store.messages == {}
    assert disabled.commands is not None
    assert isinstance(disabled.commands.store, CapturingCommandStore)
    assert disabled.commands.store._commands == {}


def test_sms_segments_suppression_tenant_isolation_and_cancel(test_settings) -> None:
    assert sms_segments("A" * 160).segments == 1
    assert sms_segments("A" * 161).segments == 2
    assert sms_segments("🙂" * 35).segments == 1
    assert sms_segments("🙂" * 36).segments == 2

    runtime = _runtime(test_settings)
    assert runtime.communications is not None
    runtime.communications.store.suppressions.add(
        ("tenant-1", "sms", "+49111111111")
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        suppressed = client.post(
            "/v1/communications/messages",
            json=_message(to=["+49111111111"]),
            headers=_headers(key="sms-suppressed"),
        )
        assert suppressed.status_code == 202
        assert suppressed.json()["status"] == "suppressed"
        assert suppressed.json()["operationId"] is None
        fetched_suppressed = client.get(
            f"/v1/communications/messages/{suppressed.json()['messageId']}",
            headers=_headers(scope="kyqra.middleware.status.read"),
        )
        assert fetched_suppressed.status_code == 200

        no_marketing_consent = client.post(
            "/v1/communications/messages",
            json=_message(
                to=["+49222222222"],
                metadata={"category": "marketing"},
            ),
            headers=_headers(key="sms-no-marketing-consent"),
        )
        assert no_marketing_consent.json()["failureCode"] == "consent_required"

        created = client.post(
            "/v1/communications/messages",
            json=_message(to=["+49333333333"]),
            headers=_headers(key="sms-cancel-create"),
        ).json()
        wrong_tenant = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(
                scope="kyqra.middleware.status.read",
                tenant="tenant-2",
            ),
        )
        assert wrong_tenant.status_code == 404
        cancelled = client.post(
            f"/v1/communications/messages/{created['messageId']}/cancel",
            headers=_headers(key="sms-cancel-operation"),
        )
        assert cancelled.status_code == 202
        assert cancelled.json()["status"] == "cancelled"
        cancel_replay = client.post(
            f"/v1/communications/messages/{created['messageId']}/cancel",
            headers=_headers(key="sms-cancel-operation"),
        )
        assert cancel_replay.status_code == 200
        assert runtime.commands is not None
        operation = asyncio.run(
            runtime.commands.store.get("tenant-1", UUID(created["operationId"]))
        )
    assert operation.state == "cancelled"


def test_signed_telnexa_dlr_is_replay_safe_and_monotonic(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="sms-dlr-create"),
        ).json()
        delivered = _event(
            event_type="codestra.sms.message.delivered",
            payload={
                "message_id": created["messageId"],
                "status": "DELIVRD",
                "provider_message_id": "jasmin-1",
            },
        )
        accepted = _post_event(client, delivered)
        assert accepted.status_code == 202, accepted.text
        duplicate = _post_event(client, delivered)
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] is True

        late_sent = _event(
            event_type="codestra.sms.message.delivered",
            payload={
                "message_id": created["messageId"],
                "status": "SENT",
                "provider_message_id": "jasmin-1",
            },
        )
        assert _post_event(client, late_sent).status_code == 202
        fetched = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="kyqra.middleware.status.read"),
        )
        assert fetched.json()["status"] == "delivered"
        assert fetched.json()["providerReference"] == "jasmin-1"
        timeline = client.get(
            f"/v1/communications/messages/{created['messageId']}/events",
            headers=_headers(scope="kyqra.middleware.status.read"),
        ).json()["items"]
        assert [item["status"] for item in timeline] == [
            "accepted",
            "queued",
            "delivered",
            "delivered",
        ]
        assert timeline[-1]["metadata"]["ignoredTransition"] is True

        changed = json.loads(json.dumps(delivered))
        changed["payload"]["status"] = "FAILED"
        assert _post_event(client, changed).status_code == 409


def test_signed_sms_mo_normalizes_stop_and_help_without_duplicate_effects(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        stop = _event(
            event_type="codestra.sms.inbound.received",
            payload={
                "inbound_message_id": "mo-stop-1",
                "sender": "+49444444444",
                "destination": "+49555555555",
                "content": "STOP",
            },
        )
        assert _post_event(client, stop).status_code == 202
        assert _post_event(client, stop).json()["duplicate"] is True
        assert runtime.communications is not None
        assert (
            "tenant-1",
            "sms",
            "+49444444444",
        ) in runtime.communications.store.suppressions

        blocked = client.post(
            "/v1/communications/messages",
            json=_message(to=["+49444444444"]),
            headers=_headers(key="sms-stop-blocked"),
        )
        assert blocked.json()["status"] == "suppressed"

        help_event = _event(
            event_type="codestra.sms.inbound.received",
            payload={
                "inbound_message_id": "mo-help-1",
                "sender": "+49666666666",
                "destination": "+49555555555",
                "content": "HELP",
            },
        )
        assert _post_event(client, help_event).status_code == 202
        listed = client.get(
            "/v1/communications/messages?channel=sms",
            headers=_headers(scope="kyqra.middleware.status.read"),
        ).json()["items"]
        inbound = [item for item in listed if item["direction"] == "inbound"]
        assert len(inbound) == 2
        assert {item["metadata"]["complianceAction"] for item in inbound} == {
            "stop",
            "help",
        }


def test_sms_unknown_outcome_is_indeterminate_without_duplicate_command(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="sms-unknown-outcome"),
        ).json()
        command_id = UUID(created["operationId"])

        async def make_uncertain() -> None:
            assert runtime.commands is not None
            transitions: tuple[tuple[CommandState, str], ...] = (
                ("queued", "workflow accepted durable intent"),
                ("dispatching", "Telnexa submission started"),
                (
                    "reconciliation_required",
                    "Telnexa timed out after possible acceptance",
                ),
            )
            for state, reason in transitions:
                await runtime.commands.store.transition(
                    "tenant-1",
                    command_id,
                    new_state=state,
                    actor_id="temporal:test",
                    reason=reason,
                )

        asyncio.run(make_uncertain())
        readback = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="kyqra.middleware.status.read"),
        )
        assert readback.json()["status"] == "indeterminate"
        assert readback.json()["failureCode"] == "provider_outcome_unknown"
        replay = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="sms-unknown-outcome"),
        )
        assert replay.status_code == 200
        assert replay.json()["messageId"] == created["messageId"]
        assert runtime.commands is not None
        assert isinstance(runtime.commands.store, CapturingCommandStore)
        assert len(runtime.commands.store.submitted) == 1
