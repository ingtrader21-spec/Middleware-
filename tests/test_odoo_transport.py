from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.commands import ODOO_COMMAND_DESTINATION, TEMPORAL_COMMAND_DESTINATION
from app.odoo_transport import (
    STATUS_PATH_TEMPLATE,
    UPSERT_PATH,
    OdooCommandDispatcher,
    OdooConfigurationError,
    OdooTransportError,
)
from app.storage import OutboxRecord
from app.worker import KnownSafeRetryError

BASE_URL = "https://odoo.internal.invalid"
SECRET = b"synthetic-odoo-signing-secret-32bytes"
TENANT = "tenant-1"


def command_payload(
    *,
    tenant_id: str = TENANT,
    campaign_code: str | None = None,
    command_id: str | None = None,
) -> dict[str, Any]:
    identity = command_id or str(uuid4())
    return {
        "command_id": identity,
        "command_type": "crm.lead.upsert",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": tenant_id,
        "requested_by": "synthetic-intake",
        "correlation_id": f"correlation-{identity}",
        "idempotency_key": f"idempotency-{identity}",
        "capability": "ODOO_WRITE",
        "payload": {
            "lead_source": "synthetic-form",
            "source_record_id": f"source-{identity}",
            "initial_stage": "new",
            "review_required": False,
            "allow_external_contact": True,
            "provenance": {
                "method": "submitted_by_person",
                "captured_by": "synthetic-form-service",
                "source_reference": f"synthetic://form/{identity}",
                "legal_basis": "consent",
                "content_digest": "a" * 64,
            },
            "consent": {
                "status": "granted",
                "captured_at": "2026-08-29T00:00:00+00:00",
                "policy_version": "synthetic-v1",
                "channels": {"email": True, "sms": False, "phone": True},
            },
            "lead": {
                "name": "Synthetic Lead",
                "description": "Synthetic intake.",
                "contact": {
                    "name": "Synthetic Contact",
                    "email": "synthetic@example.invalid",
                    "phone": "+18095550199",
                    "preferred_language": "en",
                },
                "company": {
                    "name": "Synthetic Company",
                    "domain": "example.invalid",
                    "industry": "Testing",
                },
                "campaign_code": campaign_code,
                "tags": ["synthetic-intake"],
            },
        },
    }


def outbox_record(payload: dict[str, Any], **overrides: Any) -> OutboxRecord:
    values: dict[str, Any] = {
        "id": 1,
        "tenant_id": payload["tenant_id"],
        "destination": ODOO_COMMAND_DESTINATION,
        "event_type": payload["command_type"],
        "idempotency_key": payload["idempotency_key"],
        "payload": payload,
        "attempt_count": 1,
    }
    values.update(overrides)
    return OutboxRecord(**values)


def dispatcher_for(handler, *, secrets: dict[str, bytes] | None = None):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return OdooCommandDispatcher(
        client=client,
        base_url=BASE_URL,
        secrets=secrets or {},
        source_delivery_enabled=lambda method: method == "submitted_by_person",
        default_secret=SECRET,
    )


def expected_signature(request: httpx.Request, secret: bytes = SECRET) -> str:
    canonical = b"\n".join(
        (
            request.headers["X-Codestra-Timestamp"].encode(),
            request.headers["X-Codestra-Event-ID"].encode(),
            request.method.encode(),
            request.url.path.encode(),
            request.headers["X-Tenant-ID"].encode(),
            request.headers["X-Correlation-ID"].encode(),
            request.headers["Idempotency-Key"].encode(),
            request.content,
        )
    )
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_signature_covers_the_security_headers_and_body() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"outcome": "created"})

    payload = command_payload()
    await dispatcher_for(handler).dispatch(outbox_record(payload))

    assert len(seen) == 1
    request = seen[0]
    assert request.url.path == UPSERT_PATH
    supplied = request.headers["X-Codestra-Signature"].removeprefix("sha256=")
    assert hmac.compare_digest(supplied, expected_signature(request))
    # The headers must mirror the envelope, which the bridge cross-checks.
    assert request.headers["X-Codestra-Event-ID"] == payload["command_id"]
    assert request.headers["X-Tenant-ID"] == payload["tenant_id"]
    assert request.headers["X-Correlation-ID"] == payload["correlation_id"]
    assert request.headers["Idempotency-Key"] == payload["idempotency_key"]
    # The signed bytes must be the sent bytes.
    assert json.loads(request.content) == payload


@pytest.mark.asyncio
async def test_a_swapped_identity_header_breaks_the_signature() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"outcome": "created"})

    await dispatcher_for(handler).dispatch(outbox_record(command_payload()))
    request = seen[0]
    forged = httpx.Request(
        request.method,
        request.url,
        headers={**request.headers, "X-Tenant-ID": "other-tenant"},
        content=request.content,
    )
    supplied = request.headers["X-Codestra-Signature"].removeprefix("sha256=")
    assert not hmac.compare_digest(supplied, expected_signature(forged))


@pytest.mark.asyncio
async def test_campaign_code_is_carried_in_the_signed_body() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"outcome": "created"})

    payload = command_payload(campaign_code="MWCAMP-ABC123")
    await dispatcher_for(handler).dispatch(outbox_record(payload))
    body = json.loads(seen[0].content)
    assert body["payload"]["lead"]["campaign_code"] == "MWCAMP-ABC123"


@pytest.mark.asyncio
async def test_per_tenant_secret_is_preferred_over_the_default() -> None:
    tenant_secret = b"a-distinct-tenant-secret-of-32-bytes"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"outcome": "updated"})

    dispatcher = dispatcher_for(handler, secrets={TENANT: tenant_secret})
    await dispatcher.dispatch(outbox_record(command_payload()))
    request = seen[0]
    supplied = request.headers["X-Codestra-Signature"].removeprefix("sha256=")
    assert hmac.compare_digest(supplied, expected_signature(request, tenant_secret))
    assert not hmac.compare_digest(supplied, expected_signature(request, SECRET))


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 201])
async def test_confirmed_outcome_returns_normally(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"outcome": "created"})

    await dispatcher_for(handler).dispatch(outbox_record(command_payload()))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,error",
    [
        (422, "consent_does_not_permit_contact"),
        (409, "stale_command"),
        (409, "campaign_binding_immutable"),
        (409, "mapping_target_missing"),
        (403, "tenant_rejected"),
        (401, "invalid_signature"),
    ],
)
async def test_definitive_rejection_is_quarantined_not_retried(
    status: int, error: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": error})

    with pytest.raises(OdooTransportError) as raised:
        await dispatcher_for(handler).dispatch(outbox_record(command_payload()))
    assert error in str(raised.value)
    assert not isinstance(raised.value, KnownSafeRetryError)


@pytest.mark.asyncio
async def test_connection_failure_is_a_proven_safe_retry() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(KnownSafeRetryError):
        await dispatcher_for(handler).dispatch(outbox_record(command_payload()))


@pytest.mark.asyncio
async def test_timeout_reconciles_and_accepts_a_recorded_outcome() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == UPSERT_PATH:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(200, json={"result": {"outcome": "created"}})

    payload = command_payload()
    await dispatcher_for(handler).dispatch(outbox_record(payload))
    assert paths == [
        UPSERT_PATH,
        STATUS_PATH_TEMPLATE.format(command_id=payload["command_id"]),
    ]


@pytest.mark.asyncio
async def test_timeout_reconciles_and_only_a_proven_non_delivery_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == UPSERT_PATH:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(404, json={"error": "command_not_found"})

    with pytest.raises(KnownSafeRetryError):
        await dispatcher_for(handler).dispatch(outbox_record(command_payload()))


@pytest.mark.asyncio
async def test_unreachable_reconciliation_stays_an_unknown_outcome() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    with pytest.raises(OdooTransportError) as raised:
        await dispatcher_for(handler).dispatch(outbox_record(command_payload()))
    assert not isinstance(raised.value, KnownSafeRetryError)


@pytest.mark.asyncio
async def test_reconciliation_error_is_not_downgraded_to_a_retry() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == UPSERT_PATH:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(500, json={"error": "internal"})

    with pytest.raises(OdooTransportError) as raised:
        await dispatcher_for(handler).dispatch(outbox_record(command_payload()))
    assert not isinstance(raised.value, KnownSafeRetryError)


@pytest.mark.asyncio
async def test_gateway_status_is_reconciled_rather_than_assumed() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == UPSERT_PATH:
            return httpx.Response(503)
        return httpx.Response(200, json={"result": {"outcome": "created"}})

    await dispatcher_for(handler).dispatch(outbox_record(command_payload()))
    assert len(paths) == 2


@pytest.mark.asyncio
async def test_reconciliation_uses_a_fresh_event_identity() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == UPSERT_PATH:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(200, json={"result": {}})

    payload = command_payload()
    await dispatcher_for(handler).dispatch(outbox_record(payload))
    status_request = seen[1]
    # Replaying the command's own event ID would be rejected by the bridge.
    assert status_request.headers["X-Codestra-Event-ID"] != payload["command_id"]
    assert status_request.headers["X-Tenant-ID"] == payload["tenant_id"]
    supplied = status_request.headers["X-Codestra-Signature"].removeprefix("sha256=")
    assert hmac.compare_digest(supplied, expected_signature(status_request))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"destination": TEMPORAL_COMMAND_DESTINATION},
        {"tenant_id": "other-tenant"},
        {"event_type": "crm.lead.other"},
        {"idempotency_key": "mismatched-key"},
    ],
)
async def test_outbox_row_must_agree_with_the_envelope(
    overrides: dict[str, Any]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request may be sent for a mismatched row")

    payload = command_payload()
    record = outbox_record(payload, **overrides)
    with pytest.raises(OdooTransportError):
        await dispatcher_for(handler).dispatch(record)


@pytest.mark.asyncio
async def test_unsupported_command_is_never_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request may be sent for an unsupported command")

    payload = command_payload()
    payload["target"] = "vicidial"
    record = outbox_record(payload)
    with pytest.raises(OdooTransportError):
        await dispatcher_for(handler).dispatch(record)


@pytest.mark.asyncio
async def test_disabled_source_scope_is_never_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request may be sent for a disabled source")

    payload = command_payload()
    payload["payload"]["lead_source"] = "platform-form"
    payload["payload"]["provenance"]["method"] = "crawler_discovery"
    with pytest.raises(OdooConfigurationError):
        await dispatcher_for(handler).dispatch(outbox_record(payload))


def test_plaintext_base_url_is_refused() -> None:
    with pytest.raises(OdooConfigurationError):
        OdooCommandDispatcher(
            client=httpx.AsyncClient(),
            base_url="http://odoo.internal.invalid",
            secrets={},
            source_delivery_enabled=lambda source: True,
            default_secret=SECRET,
        )


def test_missing_secret_is_refused() -> None:
    with pytest.raises(OdooConfigurationError):
        OdooCommandDispatcher(
            client=httpx.AsyncClient(),
            base_url=BASE_URL,
            secrets={},
            source_delivery_enabled=lambda source: True,
            default_secret=None,
        )


BASE_ENV = {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}
LONG_SECRET = "s" * 40


def settings_for(**overrides: str):
    from app.core.config import Settings

    return Settings.from_env({**BASE_ENV, **overrides})


def test_odoo_delivery_is_closed_by_default() -> None:
    settings = settings_for()
    assert settings.odoo_19_delivery_enabled is False


def test_enabling_odoo_write_requires_a_configured_endpoint() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(ODOO_WRITE="true")


def test_odoo_endpoint_must_be_https() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(
            ODOO_WRITE="true",
            ODOO_19_BASE_URL="http://odoo.internal.invalid",
            ODOO_19_HMAC_SECRET=LONG_SECRET,
        )


def test_odoo_secret_must_be_long_enough() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(
            ODOO_WRITE="true",
            ODOO_19_BASE_URL=BASE_URL,
            ODOO_19_HMAC_SECRET="short",
        )


def test_source_scoped_delivery_cannot_outrun_the_write_capability() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(
            FORM_ODOO_DELIVERY_ENABLED="true",
            ODOO_19_BASE_URL=BASE_URL,
            ODOO_19_HMAC_SECRET=LONG_SECRET,
        )


def test_fully_configured_odoo_delivery_validates() -> None:
    settings = settings_for(
        EXTERNAL_DELIVERY_ENABLED="true",
        ODOO_WRITE="true",
        FORM_ODOO_DELIVERY_ENABLED="true",
        ODOO_19_BASE_URL=BASE_URL,
        ODOO_19_HMAC_SECRET=LONG_SECRET,
    )
    assert settings.odoo_19_delivery_enabled is True
    assert settings.odoo_source_delivery_enabled("submitted_by_person") is True
    assert settings.odoo_source_delivery_enabled("crawler_discovery") is False
    assert settings.odoo_secret_for("any-tenant") == LONG_SECRET.encode("utf-8")


def test_source_scoped_delivery_requires_the_matching_gate() -> None:
    settings = settings_for(
        EXTERNAL_DELIVERY_ENABLED="true",
        ODOO_WRITE="true",
        CRAWLER_ODOO_DELIVERY_ENABLED="true",
        ODOO_19_BASE_URL=BASE_URL,
        ODOO_19_HMAC_SECRET=LONG_SECRET,
    )
    assert settings.odoo_source_delivery_enabled("crawler_discovery") is True
    assert settings.odoo_source_delivery_enabled("submitted_by_person") is False
    assert settings.odoo_source_delivery_enabled("unknown-source") is False


def test_per_tenant_secret_map_is_parsed_and_preferred() -> None:
    settings = settings_for(
        EXTERNAL_DELIVERY_ENABLED="true",
        ODOO_WRITE="true",
        ODOO_19_BASE_URL=BASE_URL,
        ODOO_19_HMAC_SECRET=LONG_SECRET,
        ODOO_19_TENANT_HMAC_SECRETS=json.dumps({TENANT: "t" * 40}),
    )
    assert settings.odoo_secret_for(TENANT) == b"t" * 40
    assert settings.odoo_secret_for("other") == LONG_SECRET.encode("utf-8")


def test_malformed_tenant_secret_map_fails_closed() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(ODOO_19_TENANT_HMAC_SECRETS="not-json")


def test_unimplemented_effects_still_cannot_be_enabled() -> None:
    from app.core.config import ConfigurationError

    with pytest.raises(ConfigurationError):
        settings_for(SMS_DELIVERY_ENABLED="true")
