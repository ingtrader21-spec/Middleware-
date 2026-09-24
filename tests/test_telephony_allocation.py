from app.core.telephony import (
    AUTHORITATIVE_SOURCES,
    ExtensionState,
    audit_extension,
    canonical_event,
    transition_allowed,
)


def clear_evidence():
    return {source: "ABSENT" for source in AUTHORITATIVE_SOURCES}


def test_complete_inventory_is_required_for_available():
    result = audit_extension(6110, {"pjsip_endpoint": "ABSENT"})
    assert result.classification == ExtensionState.UNKNOWN_REQUIRES_REVIEW
    assert result.missing_sources


def test_candidate_6110_only_available_with_every_authoritative_clear():
    result = audit_extension(6110, clear_evidence())
    assert result.classification == ExtensionState.AVAILABLE
    assert not result.missing_sources


def test_global_exclusions_always_fail_closed():
    assert (
        audit_extension(6101, clear_evidence()).classification
        == ExtensionState.EXCLUDED
    )
    assert (
        audit_extension(1001, clear_evidence()).classification
        == ExtensionState.EXCLUDED
    )


def test_collision_precedence():
    evidence = clear_evidence()
    evidence["vicidial_phone"] = "PRESENT"
    assert audit_extension(6110, evidence).classification == ExtensionState.ASSIGNED
    evidence["asterisk_channel"] = "ACTIVE"
    assert audit_extension(6110, evidence).classification == ExtensionState.ACTIVE


def test_history_ambiguity_holds_extension():
    evidence = clear_evidence()
    evidence["call_history"] = "AMBIGUOUS"
    assert (
        audit_extension(6110, evidence).classification == ExtensionState.HISTORICAL_HOLD
    )


def test_saga_does_not_skip_disabled_ready():
    assert transition_allowed("PROVISIONING", "DISABLED_READY")
    assert not transition_allowed("PROVISIONING", "ACTIVE")
    assert transition_allowed("DISABLED_READY", "ACTIVATION_PENDING")
    assert transition_allowed("ACTIVATION_PENDING", "ACTIVE")


def test_event_contract_contains_required_fields():
    event = canonical_event(
        "extension.reserved",
        "correlation-1",
        "idempotency-0001",
        "codestra-extension-allocator",
        "service-account",
        "TRN-A001",
        "transportation",
        "Transportation",
        "extension",
        "6110",
        1,
        {"extension": 6110},
    )
    required = {
        "schema_version",
        "event_id",
        "correlation_id",
        "idempotency_key",
        "occurred_at",
        "source",
        "actor",
        "employee_id",
        "business_unit_id",
        "campaign_id",
        "object_type",
        "object_id",
        "revision",
        "payload",
    }
    assert required <= event.keys()
    assert "password" not in str(event).lower()
