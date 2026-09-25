"""MCR-A campaign recycling contract tests.

The contracts are declarative only. These tests prove the schemas parse and
accept/reject representative documents, that enums agree across artifacts and
with the existing sources they reuse, that the API endpoint set is exact, that
suppression precedence is explicit, and that no runtime route, migration, or
production/provider activation is introduced.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from app.core.campaign_identity import format_identity
from app.core.lead_automation import canonical_hash
from scripts import validate_campaign_recycling_contracts as mcr

ROOT = Path(__file__).resolve().parents[1]
UUID_A = "00000000-0000-4000-8000-000000000001"
UUID_B = "00000000-0000-4000-8000-000000000002"
UUID_C = "00000000-0000-4000-8000-000000000003"
NOW = "2026-09-24T12:00:00Z"
SHA = "a" * 64


@pytest.fixture(scope="module")
def artifacts() -> dict[str, Any]:
    return mcr.load_artifacts()


def _fresh(artifacts: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(artifacts)


def _errors(validator: Draft202012Validator, document: dict[str, Any]) -> list[str]:
    return [error.message for error in validator.iter_errors(document)]


def _lead_id(sequence: int = 1) -> str:
    return format_identity(100, "TST", "LEAD", sequence).public_id


def _idempotency_key(**overrides: Any) -> str:
    natural = {
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "campaign_id": "klyrow:cmp_test_syn",
        "campaign_version": 1,
        "channel": "email",
        "touch_index": 1,
        **overrides,
    }
    return "mcr1:" + canonical_hash(natural)


# --- repository validator ------------------------------------------------------


def test_validator_passes_on_repository() -> None:
    assert mcr.validate() == []
    assert mcr.main() == 0


def test_every_artifact_parses() -> None:
    for path in mcr.SCHEMA_FILES.values():
        Draft202012Validator.check_schema(
            json.loads((ROOT / path).read_text(encoding="utf-8"))
        )
    api = yaml.safe_load((ROOT / mcr.OPENAPI_FILE).read_text(encoding="utf-8"))
    assert api["openapi"] == "3.1.0"
    json.loads((ROOT / mcr.AUTHORITY_FILE).read_text(encoding="utf-8"))
    json.loads((ROOT / mcr.POLICY_FILE).read_text(encoding="utf-8"))
    assert (ROOT / mcr.DOC_FILE).is_file()


# --- lifecycle -----------------------------------------------------------------


def _transition(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "transition_id": UUID_A,
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "from_state": "ACTIVE_CYCLE",
        "to_state": "ENGAGED",
        "reason_code": "STRONG_ENGAGEMENT_RECORDED",
        "source": "delivery_event",
        "lifecycle_version": 4,
        "occurred_at": NOW,
        "recorded_at": NOW,
        "correlation_id": "corr-1",
        "evidence_hash": SHA,
        **overrides,
    }


def test_lifecycle_accepts_legal_transitions(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "lifecycle")
    assert _errors(validator, _transition()) == []
    registration = _transition(
        from_state=None,
        to_state="NEW",
        reason_code="LEAD_REGISTERED",
        lifecycle_version=1,
    )
    assert _errors(validator, registration) == []
    suppression = _transition(
        from_state="CONVERTED",
        to_state="SUPPRESSED",
        reason_code="GLOBAL_SUPPRESSION_APPLIED",
        source="operator",
    )
    assert _errors(validator, suppression) == []


@pytest.mark.parametrize(
    ("from_state", "to_state", "reason"),
    [
        ("SUPPRESSED", "NEW", "LEAD_REGISTERED"),
        ("SUPPRESSED", "ELIGIBLE", "ELIGIBILITY_ESTABLISHED"),
        ("CONVERTED", "ACTIVE_CYCLE", "CYCLE_STARTED"),
        ("NEW", "ACTIVE_CYCLE", "CYCLE_STARTED"),
        ("COOLING", "ACTIVE_CYCLE", "CYCLE_STARTED"),
        ("ACTIVE_CYCLE", "ENGAGED", "CYCLE_STARTED"),
        (None, "VALIDATED", "VALIDATION_PASSED"),
    ],
)
def test_lifecycle_rejects_illegal_transitions(
    artifacts: dict[str, Any], from_state: str | None, to_state: str, reason: str
) -> None:
    validator = mcr.validator_for(artifacts, "lifecycle")
    document = _transition(from_state=from_state, to_state=to_state, reason_code=reason)
    assert _errors(validator, document)


def test_lead_id_pattern_is_the_campaign_identity_format(
    artifacts: dict[str, Any],
) -> None:
    validator = mcr.validator_for(artifacts, "lifecycle", "/$defs/LeadId")
    for campaign_number in (100, 12300, 900):
        assert validator.is_valid(
            format_identity(campaign_number, "TST", "LEAD", 7).public_id
        )
    assert not validator.is_valid(format_identity(100, "TST", "CALLBACK", 7).public_id)
    assert not validator.is_valid("TST-100-L-00000007")


def test_lifecycle_is_separate_from_dialing_eligibility(
    artifacts: dict[str, Any],
) -> None:
    separate = artifacts["lifecycle"]["x-codestra-contract"]["separate_from"]
    identity, dialing = mcr.dialing_contract_states()
    assert separate["identity_states"] == identity
    assert separate["dialing_states"] == dialing
    assert "never implies dialing ELIGIBLE" in separate["rule"]
    assert "DIALING_NOT_ELIGIBLE" in mcr._enum(artifacts["next_action"], "ReasonCode")
    broken = _fresh(artifacts)
    broken["lifecycle"]["x-codestra-contract"]["separate_from"][
        "dialing_states"
    ].remove("DO_NOT_CALL")
    assert any("drifted from lead-eligibility.md" in e for e in mcr.validate(broken))


# --- channel health --------------------------------------------------------------


def _health(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "channel": "email",
        "address_ref": "adr_0123456789",
        "state": "hard_bounce",
        "previous_state": "valid",
        "source": "klyrow_delivery_event",
        "reason_code": "HARD_BOUNCE",
        "occurred_at": NOW,
        "recorded_at": NOW,
        "evidence": {
            "kind": "delivery_event",
            "event_id": "evt_00000001",
            "evidence_hash": SHA,
        },
        "suppression": None,
        "cross_channel_effect": "none",
        "health_version": 2,
        "correlation_id": "corr-1",
        **overrides,
    }


def _suppression(scope: str = "channel", **overrides: Any) -> dict[str, Any]:
    return {
        "suppression_id": UUID_B,
        "scope": scope,
        "reason": "unsubscribe",
        "campaign_id": None,
        "occurred_at": NOW,
        **overrides,
    }


def test_channel_health_bad_email_stays_on_email(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "channel_health")
    assert _errors(validator, _health()) == []
    assert _errors(validator, _health(cross_channel_effect="sms"))
    assert _errors(validator, _health(cross_channel_effect="all_channels"))
    effects = artifacts["delivery_event"]["x-delivery-taxonomy"]["effects"]
    assert all(
        e.get("suppression", {"scope": "channel"})["scope"] == "channel"
        for e in effects.values()
    )


def test_channel_health_suppression_rules(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "channel_health")
    unsubscribed = _health(
        state="unsubscribed", reason_code="UNSUBSCRIBE", suppression=_suppression()
    )
    assert _errors(validator, unsubscribed) == []
    assert _errors(
        validator,
        _health(state="unsubscribed", reason_code="UNSUBSCRIBE", suppression=None),
    )
    assert _errors(validator, _health(suppression=_suppression()))
    provider_global = _health(
        state="suppressed",
        reason_code="SUPPRESSION_RECORDED",
        suppression=_suppression("global"),
    )
    assert _errors(validator, provider_global)
    operator_global = dict(provider_global, source="operator")
    assert _errors(validator, operator_global) == []
    assert _errors(
        validator, _health(state="suppressed", suppression=_suppression("campaign"))
    )


def test_suppression_request_scope_shape(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(
        artifacts, "channel_health", "/$defs/SuppressionRequest"
    )
    base = {
        "schema_version": "1.0",
        "lead_id": _lead_id(),
        "scope": "channel",
        "channel": "sms",
        "campaign_id": None,
        "reason": "unsubscribe",
        "source": "inbound_sms_stop",
        "occurred_at": NOW,
        "evidence": {"kind": "delivery_event", "evidence_hash": SHA},
        "requested_by": "svc-telnexa",
    }
    assert _errors(validator, base) == []
    assert _errors(validator, {**base, "channel": None})
    assert _errors(validator, {**base, "scope": "campaign_channel"})
    assert _errors(validator, {**base, "scope": "global", "channel": None})
    assert (
        _errors(
            validator,
            {**base, "scope": "global", "channel": None, "source": "operator"},
        )
        == []
    )


def test_suppression_precedence_is_explicit_and_first(
    artifacts: dict[str, Any],
) -> None:
    meta = artifacts["channel_health"]["x-channel-health"]
    policy = artifacts["policy"]["suppression"]
    assert (
        meta["suppression_scope_precedence"]
        == policy["scope_precedence"]
        == ["global", "channel", "campaign", "campaign_channel"]
    )
    assert meta["suppression_reason_precedence"] == policy["reason_precedence"]
    assert (
        policy["overrides_eligibility"] is True
        and policy["positive_signal_can_lift"] is False
    )
    codes = mcr._enum(artifacts["next_action"], "ReasonCode")
    classes = artifacts["next_action"]["x-reason-codes"]["classes"]
    first_suppression = codes.index("SUPPRESSED_GLOBAL")
    assert all(
        codes.index(c) > first_suppression
        for c, k in classes.items()
        if k in {"blocking", "temporal"}
    )

    reordered = _fresh(artifacts)
    reordered["policy"]["suppression"]["scope_precedence"].reverse()
    assert any("suppression scope precedence" in e for e in mcr.validate(reordered))
    late = _fresh(artifacts)
    precedence = late["policy"]["decision"]["reason_code_precedence"]
    precedence.remove("SUPPRESSED_GLOBAL")
    precedence.insert(precedence.index("ELIGIBLE"), "SUPPRESSED_GLOBAL")
    late["next_action"]["$defs"]["ReasonCode"]["enum"] = list(precedence)
    assert any(
        "scope precedence" in e or "before every eligibility rule" in e
        for e in mcr.validate(late)
    )


# --- exposure ledger ---------------------------------------------------------------


def _exposure(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "exposure_id": UUID_A,
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "campaign_id": "klyrow:cmp_test_syn",
        "campaign_version": 1,
        "channel": "email",
        "touch_index": 1,
        "idempotency_key": _idempotency_key(),
        "command_id": UUID_B,
        "correlation_id": "corr-1",
        "decision_id": UUID_C,
        "policy_version": "mcr-policy-1.0.0",
        "sender_identity_id": UUID_C,
        "status": "reserved",
        "engagement_outcome": "none",
        "negative_outcome": "none",
        "message_id": None,
        "provider_message_id": None,
        "reserved_at": NOW,
        "dispatched_at": None,
        "accepted_at": None,
        "delivered_at": None,
        "status_at": NOW,
        "engagement_outcome_at": None,
        "negative_outcome_at": None,
        "updated_at": NOW,
        "ledger_version": 1,
        **overrides,
    }


def test_exposure_ledger_documents(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "exposure_ledger")
    assert _errors(validator, _exposure()) == []
    delivered = _exposure(
        status="delivered",
        provider_message_id="pm-1",
        message_id=UUID_B,
        accepted_at=NOW,
        delivered_at=NOW,
        engagement_outcome="click",
        engagement_outcome_at=NOW,
    )
    assert _errors(validator, delivered) == []
    assert _errors(validator, _exposure(provider_message_id="pm-1"))
    assert _errors(validator, _exposure(status="delivered"))
    assert _errors(validator, _exposure(engagement_outcome="open"))
    assert _errors(validator, _exposure(sender_identity_id=None))
    assert _errors(validator, _exposure(idempotency_key="free-form-key"))
    for field in (
        "correlation_id",
        "command_id",
        "provider_message_id",
        "idempotency_key",
    ):
        missing = _exposure()
        del missing[field]
        assert _errors(validator, missing), field


def test_exposure_idempotency_key_is_deterministic_per_planned_touch(
    artifacts: dict[str, Any],
) -> None:
    meta = artifacts["exposure_ledger"]["x-exposure-ledger"]
    example = meta["idempotency_key_recipe"]["example_input"]
    assert list(example) == meta["natural_key"]
    assert _idempotency_key() == "mcr1:" + canonical_hash(example)
    assert _idempotency_key() == _idempotency_key()
    assert _idempotency_key(touch_index=2) != _idempotency_key()
    assert _idempotency_key(channel="sms") != _idempotency_key()
    assert _idempotency_key(campaign_version=2) != _idempotency_key()
    assert meta["unique_constraints"][0] == meta["natural_key"]
    assert ["tenant_id", "idempotency_key"] in meta["unique_constraints"]


def test_exposure_statuses_reuse_communications_status(
    artifacts: dict[str, Any],
) -> None:
    statuses = mcr._enum(artifacts["exposure_ledger"], "ExposureStatus")
    assert statuses == ["reserved", *mcr.communications_message_statuses()]
    broken = _fresh(artifacts)
    broken["exposure_ledger"]["$defs"]["ExposureStatus"]["enum"].append("bounced")
    assert any("MessageStatus" in e for e in mcr.validate(broken))


# --- next action ---------------------------------------------------------------------


def _decision(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "decision_id": UUID_A,
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "mode": "plan",
        "dry_run": True,
        "provider_effects": "none",
        "evaluated_at": NOW,
        "policy_version": "mcr-policy-1.0.0",
        "lifecycle_state": "ACTIVE_CYCLE",
        "eligible": True,
        "selected": {
            "campaign_id": "klyrow:cmp_test_syn",
            "campaign_version": 1,
            "channel": "email",
            "sender_identity_id": UUID_C,
            "touch_index": 2,
            "exposure_idempotency_key": _idempotency_key(touch_index=2),
        },
        "next_eligible_at": None,
        "reason_codes": ["ELIGIBLE"],
        "candidates": [
            {
                "campaign_id": "klyrow:cmp_test_syn",
                "campaign_version": 1,
                "channel": "email",
                "disposition": "selected",
                "reason_codes": ["ELIGIBLE"],
            },
            {
                "campaign_id": "klyrow:cmp_test_syn",
                "campaign_version": 1,
                "channel": "voice",
                "disposition": "rejected",
                "reason_codes": [
                    "DIALING_NOT_ELIGIBLE",
                    "CHANNEL_EXECUTION_NOT_SUPPORTED",
                ],
            },
        ],
        "candidates_redacted": False,
        "decision_hash": SHA,
        "correlation_id": "corr-1",
        **overrides,
    }


def test_next_action_documents(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "next_action")
    assert _errors(validator, _decision()) == []
    ineligible = _decision(
        eligible=False,
        selected=None,
        next_eligible_at=NOW,
        reason_codes=["CAMPAIGN_COOLDOWN_ACTIVE"],
        candidates=[],
        candidates_redacted=True,
    )
    assert _errors(validator, ineligible) == []
    assert _errors(validator, _decision(reason_codes=["CHANNEL_CAP_REACHED"]))
    assert _errors(validator, _decision(next_eligible_at=NOW))
    assert _errors(validator, {**ineligible, "selected": _decision()["selected"]})
    assert _errors(validator, {**ineligible, "reason_codes": ["ELIGIBLE"]})
    assert _errors(validator, _decision(dry_run=False))
    assert _errors(validator, _decision(provider_effects="email_sent"))
    assert _errors(validator, _decision(lifecycle_state="CONVERTED"))
    assert _errors(validator, _decision(lifecycle_state="COOLING"))
    assert _errors(
        validator, {**ineligible, "reason_codes": ["PRODUCTION_NOT_AUTHORIZED"]}
    )
    assert _errors(
        validator,
        {
            **ineligible,
            "candidates_redacted": True,
            "candidates": _decision()["candidates"],
        },
    )
    assert _errors(validator, _decision(policy_version="latest"))


def test_reason_codes_match_across_artifacts(artifacts: dict[str, Any]) -> None:
    codes = mcr._enum(artifacts["next_action"], "ReasonCode")
    assert codes == artifacts["policy"]["decision"]["reason_code_precedence"]
    assert set(artifacts["next_action"]["x-reason-codes"]["classes"]) == set(codes)
    assert all(f"`{code}`" in artifacts["doc"] for code in codes)
    broken = _fresh(artifacts)
    broken["policy"]["decision"]["reason_code_precedence"].pop(0)
    assert any("reason_code_precedence" in e for e in mcr.validate(broken))


def test_lifecycle_and_health_enums_match_across_artifacts(
    artifacts: dict[str, Any],
) -> None:
    lifecycle = mcr._enum(artifacts["lifecycle"], "LifecycleState")
    assert (
        lifecycle
        == mcr.LIFECYCLE_STATES
        == artifacts["lifecycle"]["x-lifecycle"]["states"]
    )
    health = mcr._enum(artifacts["channel_health"], "ChannelHealthState")
    assert (
        health
        == mcr.CHANNEL_HEALTH_STATES
        == artifacts["channel_health"]["x-channel-health"]["states"]
    )
    channels = mcr._enum(artifacts["channel_health"], "Channel")
    assert channels == artifacts["policy"]["channels"] == mcr.DESIRED_CHANNELS
    assert set(mcr.communications_channels()) < set(channels)
    assert "whatsapp" in channels
    assert artifacts["openapi"]["components"]["schemas"]["JourneyResponse"]["$ref"] == "./journey-response.v1.schema.json"
    journey = json.loads((ROOT / "contracts/campaign-recycling/journey-response.v1.schema.json").read_text())["properties"]
    assert (
        journey["lifecycle_state"]["$ref"]
        == "lifecycle.v1.schema.json#/$defs/LifecycleState"
    )
    broken = _fresh(artifacts)
    broken["channel_health"]["$defs"]["ChannelHealthState"]["enum"].append("bouncing")
    assert any("channel-health: states" in e for e in mcr.validate(broken))


# --- delivery events --------------------------------------------------------------


def _event(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": "evt_00000001",
        "event_type": "click",
        "source": "klyrow",
        "provider": "postal",
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": _lead_id(),
        "channel": "email",
        "campaign_id": "klyrow:cmp_test_syn",
        "campaign_version": 1,
        "exposure_idempotency_key": _idempotency_key(),
        "message_id": "msg-1",
        "provider_message_id": "pm-1",
        "correlation_id": "corr-1",
        "causation_id": None,
        "occurred_at": NOW,
        "received_at": NOW,
        "payload_hash": SHA,
        "automated_suspected": False,
        "origin": {
            "inbox": "klyrow_delivery_event_inbox",
            "inbox_event_id": "evt_00000001",
        },
        **overrides,
    }


def test_delivery_event_documents(artifacts: dict[str, Any]) -> None:
    validator = mcr.validator_for(artifacts, "delivery_event")
    assert _errors(validator, _event()) == []
    open_event = _event(event_type="open")
    del open_event["automated_suspected"]
    assert _errors(validator, open_event)
    assert _errors(validator, _event(event_type="hard_bounce", bounce_class="soft"))
    assert _errors(validator, _event(event_type="soft_bounce"))
    assert _errors(validator, _event(event_type="conversion"))
    assert _errors(validator, _event(event_type="bounced"))
    assert _errors(validator, _event(channel="sms"))
    assert _errors(
        validator,
        _event(origin={"inbox": "telnexa_delivery_event_inbox", "inbox_event_id": "x"}),
    )
    conversion = _event(
        event_type="conversion", source="odoo", provider=None, origin=None
    )
    del conversion["automated_suspected"]
    assert _errors(validator, conversion) == []
    assert _errors(validator, _event(origin=None))
    sms_stop = _event(
        event_type="unsubscribe", source="telnexa", channel="sms", origin=None
    )
    del sms_stop["automated_suspected"]
    assert _errors(validator, sms_stop) == []
    whatsapp_read = _event(
        event_type="read",
        source="evolution",
        provider="evolution",
        channel="whatsapp",
        campaign_id="whatsapp:cmp_test_syn",
        origin=None,
    )
    del whatsapp_read["automated_suspected"]
    assert _errors(validator, whatsapp_read) == []
    assert _errors(
        validator,
        {
            **sms_stop,
            "origin": {"inbox": "klyrow_delivery_event_inbox", "inbox_event_id": "x"},
        },
    )


def test_opens_are_weak_and_klyrow_mapping_is_complete(
    artifacts: dict[str, Any],
) -> None:
    taxonomy = artifacts["delivery_event"]["x-delivery-taxonomy"]
    assert taxonomy["event_types"] == mcr.DELIVERY_EVENT_TYPES
    assert taxonomy["signal_class"]["open"] == "weak_engagement"
    assert taxonomy["signal_class"]["read"] == "weak_engagement"
    assert taxonomy["effects"]["open"]["lifecycle"] is None
    assert taxonomy["effects"]["read"]["lifecycle"] is None
    assert taxonomy["signal_strength_order"].index("open") < taxonomy[
        "signal_strength_order"
    ].index("click")
    mapping = artifacts["delivery_event"]["x-source-mappings"]["klyrow"]["event_types"]
    assert set(mapping) == mcr.klyrow_delivery_event_types()
    assert (
        mapping["klyrow.email.bounced"]["by_bounce_class"]["unknown"] == "hard_bounce"
    )
    broken = _fresh(artifacts)
    del broken["delivery_event"]["x-source-mappings"]["klyrow"]["event_types"][
        "klyrow.email.opened"
    ]
    assert any("KlyrowDeliveryEvent" in e for e in mcr.validate(broken))
    strong_open = _fresh(artifacts)
    strong_open["delivery_event"]["x-delivery-taxonomy"]["signal_class"]["open"] = (
        "strong_engagement"
    )
    assert any("opens/reads must be weak" in e for e in mcr.validate(strong_open))


# --- API -------------------------------------------------------------------------


def test_endpoint_set_is_exact(artifacts: dict[str, Any]) -> None:
    api = artifacts["openapi"]
    operations = {
        (method, path) for path, item in api["paths"].items() for method in item
    }
    assert operations == mcr.EXPECTED_OPERATIONS
    extra = _fresh(artifacts)
    extra["openapi"]["paths"]["/platform/v1/campaign-engine/bypass"] = copy.deepcopy(
        api["paths"]["/platform/v1/campaign-engine/status"]
    )
    assert any("endpoint set must be exact" in e for e in mcr.validate(extra))
    missing = _fresh(artifacts)
    del missing["openapi"]["paths"]["/platform/v1/suppressions"]
    assert any("endpoint set must be exact" in e for e in mcr.validate(missing))
    method = _fresh(artifacts)
    method["openapi"]["paths"]["/platform/v1/campaign-engine/status"]["delete"] = {
        "responses": {}
    }
    assert any("endpoint set must be exact" in e for e in mcr.validate(method))


def test_api_controls(artifacts: dict[str, Any]) -> None:
    unsafe = _fresh(artifacts)
    del unsafe["openapi"]["paths"]["/platform/v1/campaign-engine/execute"]["post"][
        "parameters"
    ][-1]
    assert any("Idempotency-Key" in e for e in mcr.validate(unsafe))
    unsigned = _fresh(artifacts)
    unsigned["openapi"]["paths"]["/platform/v1/delivery-events"]["post"][
        "parameters"
    ].pop()
    assert any("X-Codestra-Signature" in e for e in mcr.validate(unsigned))
    unscoped = _fresh(artifacts)
    unscoped["openapi"]["paths"]["/platform/v1/suppressions"]["post"]["security"] = [
        {"codestraOAuth": []}
    ]
    assert any("exactly one declared scope" in e for e in mcr.validate(unscoped))
    effectful_plan = _fresh(artifacts)
    effectful_plan["openapi"]["paths"]["/platform/v1/campaign-engine/plan"]["post"][
        "x-codestra-effects"
    ] = "command_outbox_only"
    assert any("dry run" in e for e in mcr.validate(effectful_plan))
    envelope = artifacts["openapi"]["components"]["schemas"]["ErrorEnvelope"][
        "properties"
    ]["error"]
    assert set(envelope["required"]) == mcr.http_error_envelope_fields()


# --- no production / provider activation -----------------------------------------------


def test_no_production_or_provider_activation(artifacts: dict[str, Any]) -> None:
    policy = artifacts["policy"]
    assert policy["production"] == {
        "authorized": False,
        "lock_decision": "NO_GO",
        "live_effects_enabled": False,
        "provider_calls_enabled": False,
        "execute_enabled": False,
    }
    for name in ("staging", "production"):
        leaves = _leaves(policy["parameters"]["profiles"][name]["values"])
        assert leaves and all(value is None for value in leaves), name
    capabilities = json.loads(
        (ROOT / "config/capabilities.v2.json").read_text(encoding="utf-8")
    )["capabilities"]
    for channel, execution in policy["channel_execution"].items():
        capability = execution["capability"]
        if execution["execution"] == "blocked_pending_dependency":
            assert capabilities.get(capability) in (None, False)
            assert execution["dependency"]["url"].endswith("/Middleware-/pull/316")
        else:
            assert capabilities[capability] is False
    assert policy["channel_execution"]["voice"]["execution"] == "not_supported_in_v1"
    assert (
        policy["channel_execution"]["whatsapp"]["execution"]
        == "blocked_pending_dependency"
    )
    assert all(
        value is False
        for key, value in artifacts["authority"]["production"].items()
        if key != "lock_decision"
    )
    status = artifacts["openapi"]["components"]["schemas"]["EngineStatus"]["properties"]
    assert (
        status["engine_enabled"]["const"] is False
        and status["production_authorized"]["const"] is False
    )
    assert "servers" not in artifacts["openapi"]

    activated = _fresh(artifacts)
    activated["policy"]["production"]["authorized"] = True
    assert any(
        "production must remain unauthorized" in e for e in mcr.validate(activated)
    )
    configured = _fresh(artifacts)
    configured["policy"]["parameters"]["profiles"]["production"]["values"]["campaign"][
        "cooldown_seconds"
    ] = 60
    assert any("must stay unconfigured" in e for e in mcr.validate(configured))
    evasive = _fresh(artifacts)
    evasive["policy"]["sender_identity"]["rotation_for_deliverability_evasion"] = True
    assert any("never rotated for evasion" in e for e in mcr.validate(evasive))


def _leaves(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _leaves(item)]
    return [value]


def test_no_runtime_route_or_migration_is_introduced(
    artifacts: dict[str, Any], tmp_path: Path
) -> None:
    errors: list[str] = []
    mcr.check_no_runtime_activation(artifacts, errors, ROOT)
    assert errors == []
    handler = tmp_path / "app" / "api" / "v1" / "engine.py"
    handler.parent.mkdir(parents=True)
    handler.write_text(
        'router = APIRouter(prefix="/platform/v1/campaign-engine")\n', encoding="utf-8"
    )
    migration = tmp_path / "migrations" / "versions" / "0068_exposure.py"
    migration.parent.mkdir(parents=True)
    migration.write_text(
        'op.execute("CREATE TABLE exposure_ledger ()")\n', encoding="utf-8"
    )
    mcr.check_no_runtime_activation(artifacts, errors, tmp_path)
    assert len(errors) == 2


def test_authority_matrix(artifacts: dict[str, Any]) -> None:
    authority = artifacts["authority"]
    assert set(authority["systems"]) == mcr.REQUIRED_SYSTEMS
    assert mcr.MISSION_FOUNDATIONS <= {
        item["path"] for item in authority["reused_foundations"]
    }
    assert "post_acceptance_automation" in authority["systems"]["n8n"]["owns"]
    assert "automated_sending" in authority["systems"]["thunderbird"]["forbidden"]
    assert authority["channel_authority"]["whatsapp"] == {
        "campaign_business": "whatsapp",
        "sender_identity": "whatsapp",
        "transport": "evolution",
    }
    assert "policy_decisioning" in authority["systems"]["evolution"]["forbidden"]
    assert (
        authority["artifact_authority"]["delivery_event"]["system_of_record"]
        == "middleware"
    )
    assert (
        authority["sender_identity_rule"]["rotation_for_deliverability_evasion"]
        is False
    )
    grabby = _fresh(artifacts)
    grabby["authority"]["systems"]["n8n"]["owns"].append("direct_provider_write")
    assert any("n8n" in e for e in mcr.validate(grabby))
