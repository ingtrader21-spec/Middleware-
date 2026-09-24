"""The bodies Middleware actually sends validate against the shared Odoo schemas."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from app.adapters.odoo import results
from app.adapters.odoo.campaign_control import ActualStateReadback, load_catalog
from app.api.v1.integrations import _odoo_payload
from app.core.config import settings

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "contracts" / "odoo" / "schemas"


def schema_for(ref: str) -> dict:
    name = ref.removeprefix("internal://odoo/").removesuffix("/v1").replace("/", "-")
    document = json.loads((SCHEMAS / f"{name}.v1.json").read_text(encoding="utf-8"))
    assert document["$id"] == ref
    return document


def validate(ref: str, part: str, body: dict) -> None:
    document = schema_for(ref)
    Draft202012Validator.check_schema(document)
    validator = Draft202012Validator(document["$defs"][part], format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(body), key=lambda e: list(e.path))
    assert not errors, [e.message for e in errors]


def test_every_catalog_request_schema_ref_has_a_schema_file():
    refs = {
        spec["request_schema"]
        for spec in load_catalog()["operations"].values()
        if "request_schema" in spec
    }
    assert refs == {
        "internal://odoo/automation-results/v1",
        "internal://odoo/provider-activities/v1",
        "internal://odoo/campaigns/actual-state/v1",
        "internal://odoo/campaigns/read/v1",
        "internal://odoo/desired-state/read/v1",
    }
    for ref in refs:
        schema_for(ref)


def test_actual_state_readback_body_matches_schema():
    readback = ActualStateReadback(
        event_uuid="evt-1", command_id="cmd-1",
        idempotency_key="actual-state:evt-1:0", attempt=1,
        organization_public_id="TEST_SYN_TENANT", business_unit_public_id="TEST_SYN",
        campaign_public_id="TEST_SYN", configuration_version=1, operation="provision",
        effective_state="provisioned_disabled", manifest_ref="manifest://TEST_SYN/1",
        manifest_hash="sha256:" + "a" * 64, evidence={"adapter": "synthetic"},
        observed_at=datetime.now(UTC), correlation_id="corr-1", causation_id="evt-1",
    )
    body = readback.model_dump(mode="json")
    validate("internal://odoo/campaigns/actual-state/v1", "request", body)
    assert set(body) == set(load_catalog()["actual_state_readback"]["required_fields"])
    validate(
        "internal://odoo/campaigns/actual-state/v1", "response",
        {"status": "APPLIED", "event_uuid": "evt-1", "command_id": "cmd-1",
         "configuration_version": 1, "effective_state": "provisioned_disabled",
         "correlation_id": "corr-1", "readback_id": "rb-1"},
    )


def test_read_payloads_match_schemas():
    payload = _odoo_payload("TEST_SYN", "TEST_SYN_TENANT", "TEST_SYN")
    validate("internal://odoo/campaigns/read/v1", "request", payload)
    validate("internal://odoo/desired-state/read/v1", "request", payload)
    validate(
        "internal://odoo/desired-state/read/v1", "response",
        {"campaign_public_id": "TEST_SYN", "configuration_version": 1,
         "desired_state": "provisioned_disabled", "manifest_ref": "m", "manifest_hash": "h"},
    )


@pytest.mark.parametrize(
    "standard_result",
    [
        {"operation": "log_call_result", "phone_number": "+15555550199", "disposition": "answered",
         "call_time": 67, "call_id": "call-1", "comments": None},
        {"operation": "log_inbound_sms", "phone_number": "+15555550199", "body": "hi",
         "message_id": "sms-1", "received_at": "2026-09-16T12:00:00+00:00"},
    ],
)
def test_provider_activity_bodies_match_schema(monkeypatch, standard_result):
    monkeypatch.setattr(settings, "test_syn_odoo_organization_public_id", "TEST_SYN_TENANT")
    monkeypatch.setattr(settings, "test_syn_odoo_business_unit_public_id", "TEST_SYN")
    monkeypatch.setattr(settings, "test_syn_odoo_campaign_public_id", "TEST_SYN")
    delivery = SimpleNamespace(standard_result_json=standard_result)
    event = SimpleNamespace(original_event_id="vicidial:call-1")
    body = results._provider_activity_body(delivery, event)
    validate("internal://odoo/provider-activities/v1", "request", body)


def test_automation_result_body_matches_schema():
    delivery = SimpleNamespace(standard_result_json={
        "idempotency_key": "result:event-1:1", "workflow_key": "moneybee_offer_sent",
        "execution_id": "execution-1",
        "actions": [{"action_type": "SET_NEXT_ACTION", "entity_type": "crm.lead",
                     "entity_id": "17", "values": {"next_action_type": "CALL"}}],
    })
    event = SimpleNamespace(
        original_event_id="event-1", correlation_id="corr-1",
        payload_json={"business_unit_id": "MBL", "campaign_id": "CMP-MBL",
                      "actor_type": "AI", "actor_id": "synthetic-ai"},
    )
    body = results._campaign_action_body(delivery, event)
    validate("internal://odoo/automation-results/v1", "request", body)
