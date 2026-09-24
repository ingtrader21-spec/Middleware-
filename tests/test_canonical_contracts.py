from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from app.canonical_contracts import (
    CanonicalContractError,
    contract_schema,
    contract_validator,
    validate_contract,
    validate_specialized_contract,
)
from app.commands import CommandEnvelope
from app.models import EventEnvelope


ROOT = Path(__file__).resolve().parents[1]


def event_value() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": "provider-event-1",
        "event_type": "codestra.sms.message.delivered",
        "event_version": "1.0",
        "occurred_at": now,
        "received_at": now,
        "source": "telnexa-gateway",
        "tenant_id": "tenant-1",
        "correlation_id": "correlation-1",
        "causation_id": "command-1",
        "idempotency_key": "idempotency-event-1",
        "payload": {"message_id": "message-1"},
        "metadata": {},
    }


def command_value() -> dict:
    return {
        "command_id": "00000000-0000-4000-8000-000000000001",
        "command_type": "sms.message.submit",
        "command_version": "1.0",
        "target": "telnexa-sms",
        "tenant_id": "tenant-1",
        "requested_by": "service-1",
        "correlation_id": "correlation-1",
        "idempotency_key": "idempotency-command-1",
        "capability": "SMS_DELIVERY",
        "payload": {"message_id": "message-1"},
    }


def test_runtime_models_are_accepted_by_the_authoritative_json_schemas() -> None:
    event = EventEnvelope.model_validate(event_value())
    command = CommandEnvelope.model_validate(command_value())
    validate_contract("event", event.model_dump(mode="json", exclude_none=True))
    validate_contract("command", command.model_dump(mode="json"))


def test_contracts_reject_unknown_fields_and_unsupported_versions() -> None:
    with pytest.raises(ValidationError):
        contract_validator("event").validate(
            {**event_value(), "event_version": "2.0"}
        )
    with pytest.raises(ValidationError):
        contract_validator("command").validate(
            {**command_value(), "unreviewed": True}
        )


def test_catalog_has_one_canonical_schema_per_envelope_kind() -> None:
    catalog = json.loads(
        (
            ROOT / "contracts" / "platform" / "contract-catalog.v1.json"
        ).read_text(encoding="utf-8")
    )
    assert catalog["canonical"] == {
        "event": "contracts/platform/event-envelope.v1.schema.json",
        "command": "contracts/platform/command-envelope.v1.schema.json",
        "api": "contracts/platform/integration-fabric-api.v2.yaml",
    }
    alias = json.loads(
        (ROOT / "contracts" / "event-envelope.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert alias["$ref"] == (
        "https://contracts.codestra.co/platform/event-envelope.v1.schema.json"
    )
    assert set(contract_schema("event")["required"]) == set(
        EventEnvelope.model_fields
    ) - {"customer_id"}
    assert set(contract_schema("command")["required"]) == set(
        CommandEnvelope.model_fields
    )


def test_domain_contracts_extend_instead_of_redefine_canonical_envelopes() -> None:
    expectations = {
        "lead-intake.schema.json": (
            "https://contracts.codestra.co/platform/event-envelope.v1.schema.json"
        ),
        "odoo-lead-command.schema.json": (
            "https://contracts.codestra.co/platform/command-envelope.v1.schema.json"
        ),
    }
    for name, canonical_ref in expectations.items():
        schema = json.loads(
            (ROOT / "contracts" / name).read_text(encoding="utf-8")
        )
        assert schema["allOf"][0] == {"$ref": canonical_ref}


def test_domain_specializations_resolve_locally_and_validate_canonical_values() -> None:
    registry = Registry()
    for kind in ("event", "command"):
        schema = contract_schema(kind)  # type: ignore[arg-type]
        registry = registry.with_resource(
            schema["$id"],
            Resource.from_contents(schema),
        )

    lead_event = {
        **event_value(),
        "event_type": "codestra.lead.intake",
        "source": "kyqra-gateway",
        "payload": {
            "source_kind": "crawler_result",
            "source_system": "kyqra-crawler",
            "source_route": "crawler.kyqra.com/results",
            "submission_id": "job-1-result-1",
            "captured_at": event_value()["occurred_at"],
            "provenance": {
                "method": "crawler_discovery",
                "captured_by": "kyqra-crawler",
                "source_reference": "https://example.test/source",
                "legal_basis": "legitimate_interest_review_required",
            },
            "consent": {
                "status": "unknown",
                "channels": {"email": False, "sms": False, "phone": False},
            },
            "review": {"required": True, "reason": "crawler discovery"},
            "data": {"message": "review candidate"},
        },
    }
    lead_schema = json.loads(
        (ROOT / "contracts" / "lead-intake.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(
        lead_schema,
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(lead_event)

    odoo_command = {
        **command_value(),
        "command_type": "crm.lead.upsert",
        "target": "odoo-19",
        "capability": "ODOO_WRITE",
        "payload": {
            "lead_source": "kyqra-crawler",
            "source_record_id": "job-1-result-1",
            "initial_stage": "review_pending",
            "review_required": True,
            "allow_external_contact": False,
            "provenance": lead_event["payload"]["provenance"],
            "consent": lead_event["payload"]["consent"],
            "lead": {
                "name": "Review candidate",
                "description": None,
                "contact": None,
                "company": None,
                "tags": ["crawler-review"],
            },
        },
    }
    command_schema = json.loads(
        (ROOT / "contracts" / "odoo-lead-command.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(
        command_schema,
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(odoo_command)


def test_telnexa_sms_command_specialization_is_fail_closed() -> None:
    sms_command = {
        **command_value(),
        "command_type": "sms.message.submit.v1",
        "payload": {
            "message_id": "00000000-0000-4000-8000-000000000020",
            "channel": "sms",
            "destination": "+49123456789",
            "sender": "Telnexa",
            "content": "contract test",
            "encoding": "GSM-7",
            "characters": 13,
            "segments": 1,
            "category": "transactional",
            "client_reference": "00000000-0000-4000-8000-000000000020",
            "scheduled_at": None,
            "billing_account_id": None,
            "campaign_id": None,
        },
    }
    validate_specialized_contract("telnexa_sms_command", sms_command)
    with pytest.raises(CanonicalContractError):
        validate_specialized_contract(
            "telnexa_sms_command",
            {
                **sms_command,
                "payload": {**sms_command["payload"], "destination": "not-e164"},
            },
        )
