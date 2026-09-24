import pytest

from app.core.campaign_search import normalize_alias


@pytest.mark.parametrize(
    "value,expected",
    [
        ("cmp-100-rlp", "CMP-100-RLP"),
        ("100", "100"),
        ("rlp", "RLP"),
        ("rlp100", "RLP100"),
        ("100-l-00000001", "100-L-00000001"),
        ("RLP-100-L-00000001", "RLP-100-L-00000001"),
        ("300-C-20260728-000001", "300-C-20260728-000001"),
    ],
)
def test_exact_alias_normalization(value, expected):
    assert normalize_alias(value) == expected


@pytest.mark.parametrize(
    "value",
    ["+18095551212", "18095551212", "*", "RLP%", "../CMP-100-RLP", ""],
)
def test_phone_wildcard_and_path_search_rejected(value):
    with pytest.raises(ValueError, match="INVALID_SEARCH_ALIAS"):
        normalize_alias(value)
