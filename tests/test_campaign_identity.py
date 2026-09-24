import pytest

from app.core.campaign_identity import authorize_campaign_scope, format_identity


def test_lead_identity_and_alias():
    identity = format_identity(100, "RLP", "LEAD", 42)
    assert identity.public_id == "100-L-00000042"
    assert identity.full_alias == "RLP-100-L-00000042"


@pytest.mark.parametrize(
    "kind,kwargs,expected",
    [
        ("CALL", {"date_yyyymmdd": "20260728"}, "300-C-20260728-000007"),
        ("CALLBACK", {}, "300-CB-00000007"),
        ("TRANSFER", {}, "300-XF-00000007"),
        ("LIST", {}, "300-LST-0007"),
        ("ACTIVATION", {}, "300-ACT-007"),
        ("IMPORT_BATCH", {}, "300-IMP-007"),
        ("AGENT", {"extension": 7310}, "300-A-7310"),
    ],
)
def test_identity_formats(kind, kwargs, expected):
    assert format_identity(300, "MOY", kind, 7, **kwargs).public_id == expected


def test_identity_creation_does_not_authorize_dialing():
    identity = format_identity(500, "SCP", "LEAD", 1)
    assert not hasattr(identity, "dialing_allowed")


def test_campaign_scope_fails_closed():
    authorize_campaign_scope(100, frozenset({100}))
    with pytest.raises(PermissionError, match="CAMPAIGN_SCOPE_DENIED"):
        authorize_campaign_scope(200, frozenset({100}))


def test_sequence_width_exhaustion_fails_closed():
    with pytest.raises(ValueError, match="IDENTITY_SEQUENCE_EXHAUSTED"):
        format_identity(100, "RLP", "LIST", 10000)


@pytest.mark.parametrize(
    "number,code,kind,sequence",
    [(101, "RLP", "LEAD", 1), (100, "rlp", "LEAD", 1), (100, "RLP", "LEAD", 0)],
)
def test_invalid_identity_inputs_fail(number, code, kind, sequence):
    with pytest.raises(ValueError):
        format_identity(number, code, kind, sequence)
