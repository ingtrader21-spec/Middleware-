import pytest

from app.api.v1.campaign_search import _bearer, campaign_scope_from_claims
from app.core.jwt_auth import JWTAuthError


def claims(campaigns):
    return {
        "realm_access": {"roles": ["codestra_agent"]},
        "campaign_numbers": campaigns,
    }


def test_campaign_scope_is_derived_from_validated_claims():
    assert campaign_scope_from_claims(claims([100, "300"])) == frozenset({100, 300})


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"realm_access": {"roles": ["unrelated"]}, "campaign_numbers": [100]},
        claims([]),
        claims([101]),
        claims([True]),
        claims(["not-a-number"]),
    ],
)
def test_missing_or_invalid_scope_fails_closed(value):
    with pytest.raises(JWTAuthError):
        campaign_scope_from_claims(value)


def test_bearer_parsing_is_strict():
    assert _bearer("Bearer token-value") == "token-value"
    for value in ("", "Basic token", "Bearer", "Bearer "):
        with pytest.raises(JWTAuthError):
            _bearer(value)
