# mypy: disable_error_code="union-attr,arg-type"
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from app.commands import (
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    CommandState,
    MemoryCommandStore,
)
from app.communications import (
    CommunicationsService,
    CreateMessageRequest,
    MemoryCommunicationsStore,
)
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError, AuthorizationError
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
        try:
            claims = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except Exception as exc:
            raise AuthenticationError("invalid bearer token") from exc
        if claims.get("azp") != expected_client_id:
            raise AuthorizationError("token azp does not match producer")
        scopes = set(str(claims.get("scope") or "").split())
        if required_scope not in scopes:
            raise AuthorizationError("required scope is missing")
        return claims

    async def ready(self) -> bool:
        return True


def _runtime(test_settings, *, email_enabled: bool = True) -> Runtime:
    commands = CommandService(
        MemoryCommandStore(),
        CommandPolicyRegistry(
            (
                CommandPolicy(
                    prefix="email.",
                    target="klyrow-email",
                    capability="EMAIL_DELIVERY",
                    readback_required=True,
                ),
            ),
            {"EMAIL_DELIVERY": email_enabled},
        ),
    )
    store = MemoryCommunicationsStore()
    store.verified_senders.add(("tenant-1", "sender@codestra.co"))
    store.verified_domains.add(("tenant-1", "codestra.co"))
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=ProductTokenVerifier(),
        commands=commands,
        communications=CommunicationsService(store=store, commands=commands),
    )


def _headers(*, scope: str = "klyrow.middleware.command.write", tenant: str = "tenant-1", key: str = "email-key-1") -> dict[str, str]:
    return {
        "Authorization": "Bearer " + _token("klyrow", [scope], tenant_id=tenant),
        "X-Tenant-ID": tenant,
        "X-Correlation-ID": "email-correlation-1",
        "Idempotency-Key": key,
    }


def _message(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "channel": "email",
        "from": "sender@codestra.co",
        "to": ["person@codestra.co"],
        "content": {"subject": "Hello", "text": "Safe test message"},
        "metadata": {"consent": "granted"},
    }
    value.update(updates)
    return value


def _sign(event: dict[str, Any], path: str = "/api/v1/klyrow/events") -> dict[str, str]:
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    canonical = "\n".join(
        (
            "v1",
            "POST",
            path,
            timestamp,
            event["event_id"],
            "klyrow-gateway",
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()
    signature = hmac.new(
        b"test-secret-value-that-is-at-least-thirty-two-bytes",
        canonical,
        hashlib.sha256,
    ).hexdigest()
    return {
        "Authorization": "Bearer " + _token("klyrow-gateway", ["email.events.publish"]),
        "Content-Type": "application/json",
        "Idempotency-Key": event["event_id"],
        "X-Codestra-Event-Id": event["event_id"],
        "X-Codestra-Event-Type": event["event_type"],
        "X-Codestra-Source": "klyrow-gateway",
        "X-Codestra-Tenant-Id": event["tenant_id"],
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Signature": "sha256=" + signature,
        "X-Correlation-Id": event["correlation_id"],
    }


def test_email_message_lifecycle_idempotency_and_timeline(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        first = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(),
        )
        assert first.status_code == 202, first.text
        message = first.json()
        assert message["status"] == "queued"
        replay = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(),
        )
        assert replay.status_code == 200
        assert replay.json()["messageId"] == message["messageId"]
        conflict = client.post(
            "/v1/communications/messages",
            json=_message(content={"subject": "Changed", "text": "Changed"}),
            headers=_headers(),
        )
        assert conflict.status_code == 409
        fetched = client.get(
            f"/v1/communications/messages/{message['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert fetched.status_code == 200
        timeline = client.get(
            f"/v1/communications/messages/{message['messageId']}/events",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert [item["status"] for item in timeline.json()["items"]] == ["accepted", "queued"]
        assert runtime.communications is not None
        assert len(runtime.communications.store.messages) == 1
        assert runtime.commands is not None
        assert isinstance(runtime.commands.store, MemoryCommandStore)
        assert len(runtime.commands.store._commands) == 1


@pytest.mark.asyncio
async def test_simultaneous_duplicate_email_requests_create_one_command(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    service = runtime.communications
    assert service is not None
    request = CreateMessageRequest(**_message())
    authorization = "Bearer " + _token(
        "klyrow", ["klyrow.middleware.command.write"]
    )

    results = await asyncio.gather(
        *(
            service.submit_message(
                request,
                tenant_id="tenant-1",
                correlation_id="email-correlation-1",
                idempotency_key="simultaneous-email-key-1",
                actor="user-123",
                authorization=authorization,
                token_verifier=runtime.tokens,
            )
            for _ in range(8)
        )
    )

    assert len({str(message.messageId) for message, _ in results}) == 1
    assert sum(not duplicate for _, duplicate in results) == 1
    assert runtime.commands is not None
    assert isinstance(runtime.commands.store, MemoryCommandStore)
    assert len(runtime.commands.store._commands) == 1


def test_email_contract_validation_sender_policy_and_kill_switch(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        wrong_channel = client.post(
            "/v1/communications/messages",
            json=_message(channel="sms"),
            headers=_headers(key="wrong-channel"),
        )
        assert wrong_channel.status_code == 400
        invalid_recipient = client.post(
            "/v1/communications/messages",
            json=_message(to=["not-an-email"]),
            headers=_headers(key="invalid-recipient"),
        )
        assert invalid_recipient.status_code == 400
        unverified_sender = client.post(
            "/v1/communications/messages",
            json=_message(**{"from": "other@codestra.co"}),
            headers=_headers(key="unverified-sender"),
        )
        assert unverified_sender.status_code == 400

    disabled = _runtime(test_settings, email_enabled=False)
    disabled_app = create_app(settings=test_settings, runtime=disabled)
    with TestClient(disabled_app) as client:
        rejected = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="disabled-capability"),
        )
        assert rejected.status_code == 403
    assert disabled.communications is not None
    assert disabled.communications.store.messages == {}
    assert disabled.commands is not None
    assert isinstance(disabled.commands.store, MemoryCommandStore)
    assert disabled.commands.store._commands == {}


def test_email_suppression_and_consent_stop_before_provider_command(test_settings) -> None:
    runtime = _runtime(test_settings)
    assert runtime.communications is not None
    runtime.communications.store.suppressions.add(("tenant-1", "blocked@codestra.co"))
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        suppressed = client.post(
            "/v1/communications/messages",
            json=_message(to=["blocked@codestra.co"]),
            headers=_headers(key="suppressed-key"),
        )
        assert suppressed.status_code == 202
        assert suppressed.json()["status"] == "suppressed"
        denied = client.post(
            "/v1/communications/messages",
            json=_message(to=["needs-consent@codestra.co"], metadata={"consent": "denied"}),
            headers=_headers(key="consent-key"),
        )
        assert denied.status_code == 202
        assert denied.json()["failureCode"] == "consent_required"


def test_email_scope_tenant_and_cancellation_guards(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        wrong_scope = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(scope="klyrow.middleware.status.read", key="wrong-scope"),
        )
        assert wrong_scope.status_code == 403
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="cancel-key"),
        ).json()
        wrong_tenant = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read", tenant="tenant-2"),
        )
        assert wrong_tenant.status_code == 404
        cancelled = client.post(
            f"/v1/communications/messages/{created['messageId']}/cancel",
            headers=_headers(key="cancel-key-2"),
        )
        assert cancelled.status_code == 202
        assert cancelled.json()["status"] == "cancelled"
        again = client.post(
            f"/v1/communications/messages/{created['messageId']}/cancel",
            headers=_headers(key="cancel-key-3"),
        )
        assert again.status_code == 409


def test_communication_create_rejects_duplicate_security_headers(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    duplicate_cases = (
        ("Authorization", "Bearer duplicate-token"),
        ("X-Tenant-ID", "tenant-2"),
        ("X-Correlation-ID", "duplicate-correlation"),
        ("Idempotency-Key", "duplicate-idempotency-key"),
    )
    with TestClient(app) as client:
        for name, value in duplicate_cases:
            request_headers = list(_headers().items()) + [(name, value)]
            response = client.post(
                "/v1/communications/messages",
                content=json.dumps(_message()),
                headers=request_headers,
            )
            assert response.status_code == 400, name
            assert response.json()["error"]["code"] == "invalid_request"

        duplicate_actor = list(_headers().items()) + [
            ("X-Codestra-Actor", "user-123"),
            ("X-Codestra-Actor", "user-123"),
        ]
        response = client.post(
            "/v1/communications/messages",
            content=json.dumps(_message()),
            headers=duplicate_actor,
        )
        assert response.status_code == 400

        mismatched_actor = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers={**_headers(), "X-Codestra-Actor": "different-subject"},
        )
        assert mismatched_actor.status_code == 403

    assert runtime.communications is not None
    assert runtime.communications.store.messages == {}


def test_communication_authentication_precedes_storage_disclosure(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    runtime.commands = None
    runtime.communications = None
    request_headers = {
        **_headers(),
        "Authorization": "Bearer invalid-token",
        "X-Codestra-Actor": "user-123",
    }
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=request_headers,
        )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"


def test_communication_reads_authenticate_before_tenant_metadata(
    test_settings,
) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    request_headers = {
        **_headers(scope="klyrow.middleware.status.read"),
        "Authorization": "Bearer invalid-token",
        "X-Tenant-ID": "t" * 129,
    }
    with TestClient(app) as client:
        response = client.get(
            "/v1/communications/messages",
            headers=request_headers,
        )
    assert response.status_code == 401


def test_communication_cancel_authorizes_tenant_before_message_lookup(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    assert runtime.communications is not None
    authorization = "Bearer " + _token(
        "klyrow",
        ["klyrow.middleware.command.write"],
        tenant_id="tenant-2",
    )
    with pytest.raises(AuthorizationError, match="tenant"):
        asyncio.run(
            runtime.communications.cancel(
                "tenant-1",
                uuid4(),
                idempotency_key="cancel-unknown-message",
                actor="user-123",
                authorization=authorization,
                token_verifier=runtime.tokens,
            )
        )


def test_communication_cancel_hides_message_existence_from_wrong_channel(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="channel-probe-create"),
        ).json()
        unauthorized_headers = {
            "Authorization": "Bearer "
            + _token("kyqra", ["kyqra.middleware.command.write"]),
            "X-Tenant-ID": "tenant-1",
            "X-Correlation-ID": "channel-probe",
            "Idempotency-Key": "channel-probe-cancel",
        }
        existing = client.post(
            f"/v1/communications/messages/{created['messageId']}/cancel",
            headers=unauthorized_headers,
        )
        missing = client.post(
            f"/v1/communications/messages/{uuid4()}/cancel",
            headers={
                **unauthorized_headers,
                "Idempotency-Key": "channel-probe-missing",
            },
        )

    assert existing.status_code == missing.status_code == 404
    assert existing.json() == missing.json()
    assert runtime.communications is not None
    stored = runtime.communications.get_message(
        "tenant-1",
        UUID(created["messageId"]),
    )
    assert stored.status == "queued"


def test_klyrow_signed_event_updates_canonical_read_model(test_settings) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="callback-key"),
        ).json()
        event_id = str(uuid4())
        event = {
            "event_id": event_id,
            "event_type": "codestra.email.message.delivered",
            "event_version": "1.0",
            "occurred_at": "2026-08-29T12:00:00Z",
            "received_at": "2026-08-29T12:00:01Z",
            "source": "klyrow-gateway",
            "tenant_id": "tenant-1",
            "correlation_id": "email-correlation-1",
            "causation_id": created["messageId"],
            "idempotency_key": event_id,
            "payload": {
                "messageId": created["messageId"],
                "status": "delivered",
                "providerReference": "postal-message-1",
            },
            "metadata": {},
        }
        response = client.post(
            "/api/v1/klyrow/events",
            content=json.dumps(event, separators=(",", ":"), sort_keys=True),
            headers=_sign(event),
        )
        assert response.status_code == 202, response.text
        duplicate = client.post(
            "/api/v1/klyrow/events",
            content=json.dumps(event, separators=(",", ":"), sort_keys=True),
            headers=_sign(event),
        )
        assert duplicate.status_code == 200, duplicate.text
        assert duplicate.json()["duplicate"] is True
        fetched = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert fetched.json()["status"] == "delivered"
        assert fetched.json()["providerReference"] == "postal-message-1"
        timeline = client.get(
            f"/v1/communications/messages/{created['messageId']}/events",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert [item["status"] for item in timeline.json()["items"]] == [
            "accepted",
            "queued",
            "delivered",
        ]

        conflicting = json.loads(json.dumps(event))
        conflicting["payload"]["status"] = "bounced"
        conflict = client.post(
            "/api/v1/klyrow/events",
            content=json.dumps(conflicting, separators=(",", ":"), sort_keys=True),
            headers=_sign(conflicting),
        )
        assert conflict.status_code == 409
        after_conflict = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert after_conflict.json()["status"] == "delivered"


def test_dedicated_klyrow_event_resolves_message_by_command_identity(
    test_settings,
) -> None:
    from app.api.internal.klyrow_mail import (
        KlyrowDeliveryEvent,
        _communications_envelope,
    )

    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="dedicated-callback-key"),
        ).json()

    event = KlyrowDeliveryEvent.model_validate(
        {
            "event_id": "klyrow-delivery-event-0001",
            "schema_version": "1.0",
            "source_system": "klyrow",
            "event_type": "klyrow.email.delivered",
            "event_version": "1.0",
            "occurred_at": "2026-09-12T12:00:00Z",
            "tenant_id": "tenant-1",
            "operation_id": created["operationId"],
            "payload_hash": "a" * 64,
            "message_id": "klyrow-message-0001",
            "provider_message_id": "postal-message-0001",
            "stream": "transactional",
            "recipient_reference": "sha256:recipient-0001",
            "status": "delivered",
            "provider": "postal",
            "correlation_id": "email-correlation-1",
            "causation_id": created["operationId"],
            "attempt": 1,
            "metadata": {},
        }
    )
    envelope = _communications_envelope(event)
    assert runtime.communications is not None
    assert asyncio.run(
        runtime.communications.record_provider_event(envelope)
    ) is True
    assert asyncio.run(
        runtime.communications.record_provider_event(envelope)
    ) is False
    projected = runtime.communications.get_message(
        "tenant-1", UUID(created["messageId"])
    )
    assert projected.status == "delivered"
    assert projected.providerReference == "postal-message-0001"


def test_email_unknown_command_outcome_is_indeterminate_without_resubmission(
    test_settings,
) -> None:
    runtime = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="unknown-outcome"),
        ).json()

        assert runtime.commands is not None
        assert isinstance(runtime.commands.store, MemoryCommandStore)
        command_id = UUID(created["operationId"])

        async def make_outcome_uncertain() -> None:
            assert runtime.commands is not None
            transitions: tuple[tuple[CommandState, str], ...] = (
                ("queued", "workflow accepted durable intent"),
                ("dispatching", "provider call started"),
                (
                    "reconciliation_required",
                    "provider timed out after possible acceptance",
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

        asyncio.run(make_outcome_uncertain())

        readback = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert readback.status_code == 200
        assert readback.json()["status"] == "indeterminate"
        assert readback.json()["failureCode"] == "provider_outcome_unknown"

        replay = client.post(
            "/v1/communications/messages",
            json=_message(),
            headers=_headers(key="unknown-outcome"),
        )
        assert replay.status_code == 200
        assert replay.json()["messageId"] == created["messageId"]
        assert replay.json()["status"] == "indeterminate"
        assert len(runtime.commands.store._commands) == 1

        timeline = client.get(
            f"/v1/communications/messages/{created['messageId']}/events",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert [item["status"] for item in timeline.json()["items"]] == [
            "accepted",
            "queued",
            "indeterminate",
        ]
