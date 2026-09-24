import pytest

from app.core.lead_reconciliation import (
    Candidate,
    MatchStatus,
    OdooIdentity,
    SuppressionActive,
    SuppressionUnavailable,
    SyncAction,
    decide_action,
    idempotency_key,
    normalize_email,
    normalize_phone,
    resolve_identity,
)


def test_canonical_normalization_is_conservative():
    assert normalize_phone("(555) 123-4567", "1") == "+15551234567"
    assert normalize_phone("020 1234 5678") is None
    assert normalize_phone("123") is None
    assert normalize_email(" Person+tag@Example.COM ") == "person+tag@example.com"
    assert normalize_email("broken") is None


def test_existing_mapping_has_absolute_priority():
    mapped = Candidate("crm.lead", 10)
    other = Candidate("res.partner", 20)
    result = resolve_identity(
        mapped=mapped,
        external_reference=other,
        phone_candidates=[other],
        email_candidates=[other],
    )
    assert result.status == MatchStatus.MAPPED
    assert result.candidate == mapped


def test_phone_and_email_ambiguity_never_auto_merges():
    one = Candidate("res.partner", 1)
    two = Candidate("res.partner", 2)
    assert (
        resolve_identity(
            mapped=None,
            external_reference=None,
            phone_candidates=[one, two],
            email_candidates=[],
        ).status
        == MatchStatus.REVIEW_REQUIRED
    )
    assert (
        resolve_identity(
            mapped=None,
            external_reference=None,
            phone_candidates=[],
            email_candidates=[one, two],
        ).status
        == MatchStatus.REVIEW_REQUIRED
    )


def test_cross_channel_identity_conflict_blocks_update_and_create():
    result = resolve_identity(
        mapped=None,
        external_reference=None,
        phone_candidates=[Candidate("res.partner", 1)],
        email_candidates=[Candidate("res.partner", 2)],
    )
    assert result.status == MatchStatus.IDENTITY_CONFLICT
    assert (
        decide_action(
            result,
            suppression_available=True,
            suppression_active=False,
            consent="granted",
            eligible=True,
            payload_changed=True,
        )
        == SyncAction.IDENTITY_CONFLICT
    )


def test_suppression_fails_closed_before_create_or_update():
    unmatched = resolve_identity(
        mapped=None, external_reference=None, phone_candidates=[], email_candidates=[]
    )
    with pytest.raises(SuppressionUnavailable, match="SUPPRESSION_STATE_UNAVAILABLE"):
        decide_action(
            unmatched,
            suppression_available=False,
            suppression_active=False,
            consent="granted",
            eligible=True,
            payload_changed=True,
        )
    with pytest.raises(SuppressionActive, match="SUPPRESSION_ACTIVE"):
        decide_action(
            unmatched,
            suppression_available=True,
            suppression_active=True,
            consent="granted",
            eligible=True,
            payload_changed=True,
        )


def test_idempotency_is_stable_per_revision_campaign_and_connector():
    identity = OdooIdentity("1", "staging", "c1", "crm.lead", 42, "7")
    assert idempotency_key(identity, "LIST_A") == (
        "odoo:crm.lead:42:campaign:LIST_A:7:vicidial:c1"
    )
