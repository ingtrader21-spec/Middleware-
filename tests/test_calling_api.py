"""HTTP-level tests of the real router and existing command ledger (no phone calls)."""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.calling_contract import CAPABILITY, CLIENT_ID, HANGUP, TARGET
from app.calling_ledger import operation_response
from app.commands import CommandEnvelope, CommandError, CommandOperation, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.security import AuthenticationError, SecurityError, validate_claims
from app.telephony_api import compat_router, router
from tests.test_calling_contract import SOURCE_SHA, grant, originate, principal


class FakeCallingTokens:
    def __init__(self):
        self.claims = principal().model_dump()
        self.claims["sub"] = self.claims.pop("subject")
        self.claims.update(azp=CLIENT_ID, iat=time.time()-1, exp=time.time()+200,
                           scope=" ".join(f"telephony.calls.{action}" for action in ["originate", "read", "hangup", "reconcile"]))

    async def verify(self, authorization, *, expected_client_id, required_scope):
        if authorization != "Bearer synthetic-test-token":
            raise AuthenticationError("invalid test token")
        validate_claims(self.claims, expected_client_id=expected_client_id, required_scope=required_scope)
        return dict(self.claims)


def test_completed_hangup_response_uses_bound_originate_evidence_identity():
    now = datetime.now(UTC)
    original_id = "00000000-0000-4000-8000-000000000010"
    hangup_id = UUID("00000000-0000-4000-8000-000000000011")
    document = CommandEnvelope(
        command_id=hangup_id, command_type=HANGUP, command_version="1.0",
        target=TARGET, tenant_id="tenant-test", requested_by="subject-appolon",
        correlation_id="test-correlation-0001", idempotency_key="hangup-key",
        capability=CAPABILITY, payload={"origin_operation_id": original_id},
    )
    operation = CommandOperation(
        command_id=hangup_id, command_type=HANGUP, command_version="1.0",
        target=TARGET, tenant_id="tenant-test", requested_by="subject-appolon",
        correlation_id="test-correlation-0001", idempotency_key="hangup-key",
        capability=CAPABILITY, state="completed", created_at=now, updated_at=now,
        readback_evidence_sha256="a" * 64,
        readback_evidence={
            "operation_id": original_id, "tenant_id": "tenant-test",
            "call_state": "completed", "internal_only": True,
            "external_dialing": False,
        },
    )
    response = operation_response(operation, document)
    assert response["dialing"] == "unknown"
    assert response["reason"] == "terminal call outcome reconciled; see call_state"


async def asgi_request(app, method, path, body=None, headers=None, extra_headers=None):
    raw = json.dumps(body).encode() if body is not None else b""
    incoming = {"Authorization": "Bearer synthetic-test-token", "Content-Type": "application/json",
                "X-Correlation-ID": "test-correlation-0001"}
    if isinstance(body, dict) and "idempotency_key" in body:
        incoming["Idempotency-Key"] = body["idempotency_key"]
    incoming.update(headers or {})
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "scheme": "https", "path": path, "raw_path": path.encode(),
             "root_path": "", "query_string": b"", "server": ("testserver", 443),
             "client": ("127.0.0.1", 1),
             "headers": [(k.lower().encode(), v.encode()) for k, v in incoming.items()] +
                        [(k.lower().encode(), v.encode()) for k, v in (extra_headers or [])]}
    messages = []
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    data = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return start["status"], json.loads(data), dict(start.get("headers", []))


class CallingApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = FastAPI()
        self.app.include_router(router)
        self.app.include_router(compat_router)
        self.store = MemoryCommandStore()
        self.tokens = FakeCallingTokens()
        self.runtime = SimpleNamespace(commands=CommandService(self.store, CommandPolicyRegistry.load()),
                                       tokens=self.tokens, settings=SimpleNamespace(allow_in_memory_storage=True, source_sha=SOURCE_SHA))
        self.app.state.runtime = self.runtime

        async def safe_error(request: Request, error):
            return JSONResponse(status_code=error.status_code, content={"error": error.code})
        self.app.add_exception_handler(CommandError, safe_error)
        self.app.add_exception_handler(SecurityError, safe_error)
        self.policy = patch("app.telephony_api.calling_grant", return_value=grant())
        self.policy_mock = self.policy.start()
        self.addCleanup(self.policy.stop)

    async def call(self, body=None, **kwargs):
        return await asgi_request(self.app, "POST", "/v1/telephony/calls/originate",
                                  body or originate().model_dump(), **kwargs)

    async def test_compatibility_originate_route_reuses_internal_only_handler(self):
        body = originate().model_dump()
        status, response, _ = await asgi_request(
            self.app, "POST", "/v1/calls/originate", body,
        )
        self.assertEqual(status, 202)
        self.assertEqual(response["dialing"], "unknown")
        self.assertEqual(response["external_dialing"], False)
        self.assertEqual(len(self.store._commands), 1)

    async def test_compatibility_route_never_accepts_external_destination(self):
        status, response, _ = await asgi_request(
            self.app, "POST", "/v1/calls/originate",
            originate(destination_class="mobile", destination="+12025550124").model_dump(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["dialing"], "blocked")
        self.assertFalse(self.store._commands)

    async def test_compatibility_route_replays_same_operation_without_duplicate(self):
        body = originate().model_dump()
        first_status, first, _ = await asgi_request(
            self.app, "POST", "/v1/calls/originate", body,
        )
        second_status, second, _ = await asgi_request(
            self.app, "POST", "/v1/calls/originate", body,
        )
        self.assertEqual((first_status, second_status), (202, 200))
        self.assertEqual(first["operation_id"], second["operation_id"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(self.store._commands), 1)

    async def accept_call(self):
        _, data, _ = await self.call()
        identity = UUID(data["operation_id"])
        for state in ["queued", "dispatching", "accepted"]:
            await self.store.transition(principal().tenant_id, identity, new_state=state,
                                        actor_id="test-worker", reason="synthetic", provider_operation_id="test-asterisk-id" if state == "accepted" else None)
        return identity

    def test_routes_are_mounted_in_canonical_application(self):
        from app.core.config import Settings
        from app.main import create_app
        paths = create_app(settings=Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})).openapi()["paths"]
        for path in ["/v1/telephony/calls/originate", "/v1/calls/originate",
                     "/v1/telephony/calls/requests/{operation_id}",
                     "/v1/telephony/calls/requests/{operation_id}/reconcile", "/v1/telephony/calls/requests/{operation_id}/hangup"]:
            self.assertIn(path, paths)

    async def test_queue_is_not_reported_as_answered_or_attempting(self):
        status, body, headers = await self.call()
        self.assertEqual(status, 202)
        self.assertEqual(body["dialing"], "unknown")
        self.assertEqual(body["operation_state"], "persisted")
        self.assertIsNone(body["call_id"])
        self.assertFalse(body["retry_safe"])
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(len(self.store._commands), 1)

    async def test_matching_retry_reuses_request(self):
        _, first, _ = await self.call()
        status, second, _ = await self.call()
        self.assertEqual(status, 200)
        self.assertEqual(first["operation_id"], second["operation_id"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(self.store._commands), 1)

    async def test_retry_after_gate_closes_does_not_report_false_rejection(self):
        identity = await self.accept_call()
        self.policy_mock.return_value = None
        status, body, _ = await self.call()
        self.assertEqual(status, 200)
        self.assertEqual(body["operation_id"], str(identity))
        self.assertEqual(body["dialing"], "attempting")

    async def test_retry_with_changed_content_is_conflict(self):
        await self.call()
        status, _, _ = await self.call(originate(destination="internal:OTHER").model_dump())
        self.assertEqual(status, 409)
        self.assertEqual(len(self.store._commands), 1)

    async def test_concurrent_duplicates_create_one_command(self):
        responses = await asyncio.gather(*[self.call() for _ in range(12)])
        self.assertEqual(sum(status == 202 for status, _, _ in responses), 1)
        self.assertEqual(len({body["operation_id"] for _, body, _ in responses}), 1)
        self.assertEqual(len(self.store._commands), 1)

    async def test_second_key_cannot_reuse_one_call_authorization(self):
        await self.call()
        status, _, _ = await self.call(originate(idempotency_key="different-key-0002").model_dump())
        self.assertEqual(status, 409)

    async def test_new_grant_does_not_bypass_unknown_agent_call(self):
        await self.call()
        self.policy_mock.return_value = grant(authorization_reference="TEST-AUTH-0002")
        status, _, _ = await self.call(originate(idempotency_key="different-key-0002").model_dump())
        self.assertEqual(status, 409)

    async def test_external_destination_remains_disabled(self):
        status, body, _ = await self.call(originate(destination_class="mobile", destination="+12025550124").model_dump())
        self.assertEqual(status, 200)
        self.assertEqual(body["dialing"], "blocked")
        self.assertFalse(self.store._commands)

    async def test_absent_grant_is_disabled(self):
        self.policy_mock.return_value = None
        status, body, _ = await self.call()
        self.assertEqual(status, 200)
        self.assertEqual(body["dialing"], "blocked")
        self.assertFalse(self.store._commands)

    async def test_expired_or_wrong_release_grant_rejected(self):
        self.policy_mock.return_value = grant(source_sha="b"*40)
        status, _, _ = await self.call()
        self.assertEqual(status, 403)
        self.assertFalse(self.store._commands)

    async def test_missing_bearer_rejected(self):
        status, _, _ = await self.call(headers={"Authorization": ""})
        self.assertEqual(status, 401)
        self.assertFalse(self.store._commands)

    async def test_wrong_scope_or_client_rejected(self):
        for field, value in [("scope", "unrelated"), ("azp", "n8n-automation")]:
            old = self.tokens.claims[field]
            self.tokens.claims[field] = value
            status, _, _ = await self.call()
            self.assertEqual(status, 403)
            self.tokens.claims[field] = old
        self.assertFalse(self.store._commands)

    async def test_payload_cannot_override_agent_or_campaign(self):
        for changes in [dict(employee_id="OTHER"), dict(campaign="OTHER"), dict(business_unit="OTHER")]:
            status, _, _ = await self.call(originate(**changes).model_dump())
            self.assertEqual(status, 403)
        self.assertFalse(self.store._commands)

    async def test_missing_identity_claim_is_rejected(self):
        del self.tokens.claims["employee_id"]
        status, _, _ = await self.call()
        self.assertEqual(status, 403)

    async def test_headers_must_agree(self):
        for headers, expected in [({"Idempotency-Key": "different-key"}, 400),
                                  ({"X-Correlation-ID": "bad"}, 400), ({"X-Tenant-ID": "OTHER"}, 403)]:
            status, _, _ = await self.call(headers=headers)
            self.assertEqual(status, expected)
        self.assertFalse(self.store._commands)

    async def test_duplicate_security_headers_are_rejected(self):
        for name, values in [
            ("Authorization", ["Bearer duplicate-token"]),
            ("Idempotency-Key", ["test-originate-duplicate"]),
            ("X-Correlation-ID", ["test-correlation-duplicate"]),
            ("X-Tenant-ID", ["tenant-test", "tenant-other"]),
        ]:
            status, _, _ = await self.call(
                extra_headers=[(name, value) for value in values]
            )
            self.assertEqual(status, 400, name)
        self.assertFalse(self.store._commands)

    async def test_authentication_precedes_optional_tenant_validation(self):
        status, _, _ = await self.call(
            headers={"Authorization": "Bearer invalid", "X-Tenant-ID": "x" * 129}
        )
        self.assertEqual(status, 401)
        self.assertFalse(self.store._commands)

    async def test_request_validation_does_not_persist(self):
        body = originate().model_dump() | {"trunk": "untrusted"}
        status, _, _ = await self.call(body)
        self.assertEqual(status, 422)
        self.assertFalse(self.store._commands)

    async def test_status_is_same_actor_same_campaign_only(self):
        _, body, _ = await self.call()
        path = body["status_url"]
        status, _, _ = await asgi_request(self.app, "GET", path)
        self.assertEqual(status, 200)
        for field, value in [("sub", "other-subject"), ("tenant_id", "OTHER"), ("campaign_id", "OTHER")]:
            old = self.tokens.claims[field]
            self.tokens.claims[field] = value
            status, _, _ = await asgi_request(self.app, "GET", path)
            self.assertEqual(status, 404)
            self.tokens.claims[field] = old

    async def test_hangup_requires_authoritative_call_identity(self):
        _, body, _ = await self.call()
        status, _, _ = await asgi_request(self.app, "POST", body["status_url"]+"/hangup",
                                         dict(idempotency_key="test-hangup-0001", expected_version=1, reason="Agent hangup"))
        self.assertEqual(status, 409)
        self.assertEqual(len(self.store._commands), 1)

    async def test_bound_hangup_is_durable_and_idempotent(self):
        identity = await self.accept_call()
        path = f"/v1/telephony/calls/requests/{identity}/hangup"
        mutation = dict(idempotency_key="test-hangup-0001", expected_version=1, reason="Agent hangup")
        first_status, first, _ = await asgi_request(self.app, "POST", path, mutation)
        second_status, second, _ = await asgi_request(self.app, "POST", path, mutation)
        self.assertEqual((first_status, second_status), (202, 200))
        self.assertEqual(first["hangup_operation_id"], second["hangup_operation_id"])
        self.assertEqual(first["call_id"], "test-asterisk-id")
        self.assertEqual(len(self.store._commands), 2)

    async def test_owner_can_status_and_reconcile_hangup_after_start_grant_expiry(self):
        identity = await self.accept_call()
        mutation = dict(
            idempotency_key="test-hangup-status-0001", expected_version=1,
            reason="Agent hangup",
        )
        status, created, _ = await asgi_request(
            self.app, "POST",
            f"/v1/telephony/calls/requests/{identity}/hangup", mutation,
        )
        self.assertEqual(status, 202)
        hangup_id = created["hangup_operation_id"]
        self.policy_mock.side_effect = AssertionError(
            "read/end of an existing call must not reload the expired start grant"
        )
        status, observed, _ = await asgi_request(
            self.app, "GET", f"/v1/telephony/calls/requests/{hangup_id}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(observed["operation_id"], hangup_id)
        status, reconciled, _ = await asgi_request(
            self.app, "POST", f"/v1/telephony/calls/requests/{hangup_id}/reconcile",
            dict(idempotency_key="test-hangup-reconcile-0001", expected_version=1,  # gitleaks:allow test fixture
                 reason="Reconcile uncertain hangup"),
        )
        self.assertEqual(status, 202)
        self.assertEqual(reconciled["operation_id"], hangup_id)

        self.tokens.claims["sub"] = "subject-other"
        denied, _, _ = await asgi_request(
            self.app, "GET", f"/v1/telephony/calls/requests/{hangup_id}",
        )
        self.assertEqual(denied, 404)

    async def test_hangup_relationship_tampering_and_hangup_of_hangup_are_denied(self):
        identity = await self.accept_call()
        mutation = dict(
            idempotency_key="test-hangup-relation-0001", expected_version=1,  # gitleaks:allow test fixture
            reason="Agent hangup",
        )
        status, created, _ = await asgi_request(
            self.app, "POST",
            f"/v1/telephony/calls/requests/{identity}/hangup", mutation,
        )
        self.assertEqual(status, 202)
        hangup_id = UUID(created["hangup_operation_id"])

        nested_status, _, _ = await asgi_request(
            self.app, "POST",
            f"/v1/telephony/calls/requests/{hangup_id}/hangup",
            dict(idempotency_key="test-nested-hangup-0001", expected_version=1,
                 reason="Invalid nested hangup"),
        )
        self.assertEqual(nested_status, 409)
        self.assertEqual(len(self.store._commands), 2)

        ledger = self.runtime._calling_ledger
        durable = ledger._documents[(principal().tenant_id, hangup_id)]
        for payload_update in (
            {"origin_operation_id": str(hangup_id)},
            {"actor": durable.payload["actor"] | {"extension": "6999"}},
            {"call_id": "different-provider-call"},
        ):
            ledger._documents[(principal().tenant_id, hangup_id)] = (
                durable.model_copy(update={
                    "payload": durable.payload | payload_update,
                })
            )
            denied, _, _ = await asgi_request(
                self.app, "GET", f"/v1/telephony/calls/requests/{hangup_id}",
            )
            self.assertEqual(denied, 404)
        ledger._documents[(principal().tenant_id, hangup_id)] = durable

    async def test_reconciliation_does_not_resubmit_originate(self):
        identity = await self.accept_call()
        status, _, _ = await asgi_request(self.app, "POST", f"/v1/telephony/calls/requests/{identity}/reconcile",
                                         dict(idempotency_key="test-reconcile-0001", expected_version=1, reason="Read back outcome"))
        self.assertEqual(status, 202)
        self.assertEqual(len(self.store._commands), 1)
        current = await self.store.get(principal().tenant_id, identity)
        self.assertEqual(current.state, "reconciliation_required")

    def test_global_capabilities_are_not_enabled(self):
        policies = self.runtime.commands.policies
        self.assertFalse(policies.capabilities[CAPABILITY])
        self.assertFalse(policies.capabilities["PRODUCTION_DIALING"])
        self.assertTrue(any(item.prefix == "telephony-internal." for item in policies.policies))


if __name__ == "__main__":
    unittest.main()
