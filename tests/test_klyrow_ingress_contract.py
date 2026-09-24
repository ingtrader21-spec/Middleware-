"""Klyrow ingress contract conformance.

The klyrow-email connector manifest declares the inbound events Klyrow emits and
``config/api-webhook-contracts.json`` declares the event types the contracted
ingress route accepts. Nothing cross-checked the two, so
``email.message.unsubscribed.v1`` was declared by the connector while the route
omitted it, and ``app/service.py`` rejected every unsubscribe with 422
``event_type_not_allowed``.

These tests keep the two authorities aligned in both directions: everything the
connector can send is accepted, and everything else is still refused.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import make_event, signed_headers
from tests.test_communications_email import _headers, _message, _runtime, _sign

KLYROW_ROUTE_PATH = "/api/v1/klyrow/events"
KLYROW_PRODUCER = "klyrow-gateway"
KLYROW_SCOPE = "email.events.publish"

CONTRACT_PATH = Path("config/api-webhook-contracts.json")
MANIFEST_PATH = Path("connectors/manifests/klyrow-email.connector.json")

# The manifest and the ingress contract use different naming conventions
# (email.inbound.received.v1 is codestra.email.message.inbound), so the
# correspondence is stated explicitly. Deriving it mechanically reports false
# drift on events that are in fact covered.
MANIFEST_TO_CONTRACT_EVENT = {
    "email.message.delivered.v1": "codestra.email.message.delivered",
    "email.message.bounced.v1": "codestra.email.message.bounced",
    "email.message.complained.v1": "codestra.email.message.complained",
    "email.message.unsubscribed.v1": "codestra.email.message.unsubscribed",
    "email.inbound.received.v1": "codestra.email.message.inbound",
}


def _klyrow_route() -> dict[str, Any]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    route: dict[str, Any] = next(
        item for item in contract["webhooks"] if item["path"] == KLYROW_ROUTE_PATH
    )
    return route


def _post(client: TestClient, event: dict[str, Any]):
    body, headers = signed_headers(
        path=KLYROW_ROUTE_PATH,
        producer=KLYROW_PRODUCER,
        scope=KLYROW_SCOPE,
        event=event,
    )
    return client.post(KLYROW_ROUTE_PATH, content=body, headers=headers)


def test_every_manifest_inbound_event_has_a_contracted_ingress_type() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    declared = {
        event["event_type"]
        for event in manifest["events"]
        if event["direction"] == "inbound"
    }
    assert declared == set(MANIFEST_TO_CONTRACT_EVENT), (
        "klyrow-email manifest inbound events changed; update the explicit "
        "manifest-to-contract mapping and the ingress contract together"
    )
    allowed = set(_klyrow_route()["eventTypes"])
    missing = sorted(
        manifest_type
        for manifest_type, contract_type in MANIFEST_TO_CONTRACT_EVENT.items()
        if contract_type not in allowed
    )
    assert not missing, f"manifest events with no contracted ingress type: {missing}"


def test_ingress_accepts_every_contracted_event_type(test_settings, runtime) -> None:
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        for index, event_type in enumerate(sorted(_klyrow_route()["eventTypes"])):
            event = make_event(
                producer=KLYROW_PRODUCER,
                event_type=event_type,
                event_id=f"evt-contracted{index:04d}",
            )
            response = _post(client, event)
            assert response.status_code == 202, f"{event_type}: {response.text}"


def test_ingress_still_rejects_an_uncontracted_event_type(
    test_settings, runtime
) -> None:
    event = make_event(
        producer=KLYROW_PRODUCER,
        event_type="codestra.email.message.not_in_contract",
        event_id="evt-uncontracted01",
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = _post(client, event)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "event_type_not_allowed"


def test_unsubscribe_is_accepted(test_settings, runtime) -> None:
    """Pins the exact regression, independent of the config-derived tests.

    The two tests above both read the contract, so deleting the unsubscribe
    entry and its mapping row together would leave them self-consistent and
    green while the defect returned. This one names the event type literally,
    so the reintroduced bug fails here even if the authorities agree with each
    other.
    """
    event = make_event(
        producer=KLYROW_PRODUCER,
        event_type="codestra.email.message.unsubscribed",
        event_id="evt-unsubscribe0001",
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = _post(client, event)
    assert response.status_code == 202, response.text


def test_unsubscribe_suppresses_recipient_before_ack(test_settings) -> None:
    runtime = _runtime(test_settings)
    assert runtime.communications is not None
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        created = client.post(
            "/v1/communications/messages",
            json=_message(to=["person@codestra.co"]),
            headers=_headers(key="unsubscribe-source"),
        ).json()
        event = make_event(
            producer=KLYROW_PRODUCER,
            event_type="codestra.email.message.unsubscribed",
            event_id="evt-unsubscribe0002",
            data={
                "messageId": created["messageId"],
                "recipient": "PERSON@codestra.co",
                "status": "unsubscribed",
            },
        )
        response = client.post(
            KLYROW_ROUTE_PATH,
            content=json.dumps(event, separators=(",", ":"), sort_keys=True),
            headers=_sign(event),
        )
        assert response.status_code == 202, response.text
        assert ("tenant-1", "email", "person@codestra.co") in (
            runtime.communications.store.suppressions
        )
        fetched = client.get(
            f"/v1/communications/messages/{created['messageId']}",
            headers=_headers(scope="klyrow.middleware.status.read"),
        )
        assert fetched.json()["status"] == "suppressed"
        blocked = client.post(
            "/v1/communications/messages",
            json=_message(to=["person@codestra.co"]),
            headers=_headers(key="unsubscribe-blocked"),
        )
        assert blocked.status_code == 202
        assert blocked.json()["status"] == "suppressed"
        assert blocked.json()["failureCode"] == "recipient_suppressed"
