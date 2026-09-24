import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.jwt_auth import JWTAuthError, KeycloakValidator


ISSUER = "https://auth.example.invalid/realms/codestra"
AUDIENCE = "codestra-scraper-ingress"


def validator(public_key, monkeypatch):
    class SigningKey:
        key = public_key

    class JWKClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, _token):
            return SigningKey()

    monkeypatch.setattr(jwt, "PyJWKClient", JWKClient)
    return KeycloakValidator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://auth.example.invalid/certs",
        authorized_parties=frozenset({"scraper-c"}),
        required_roles=frozenset({"scraper-publisher"}),
        required_scopes=frozenset({"scraper.events.write"}),
        required_environment="staging",
        required_campaign="TEST_SYN",
    )


def claims(now):
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "azp": "scraper-c",
        "sub": "scraper-c",
        "iat": now,
        "exp": now + 300,
        "tenant_id": "TENANT-SYNTHETIC",
        "environment": "staging",
        "campaigns": ["TEST_SYN"],
        "realm_access": {"roles": ["scraper-publisher"]},
        "scope": "scraper.events.write",
    }


def test_scraper_service_jwt_accepts_exact_rs256_claims(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    token = jwt.encode(claims(now), private_key, algorithm="RS256")
    accepted = validator(private_key.public_key(), monkeypatch).validate(token)
    assert accepted["tenant_id"] == "TENANT-SYNTHETIC"


@pytest.mark.parametrize(
    "mutation",
    (
        {"iss": "https://wrong.example.invalid/realms/codestra"},
        {"aud": "wrong-audience"},
        {"azp": "wrong-client"},
        {"realm_access": {"roles": []}},
        {"scope": "wrong.scope"},
        {"environment": "production"},
        {"campaigns": ["UNAPPROVED"]},
        {"exp": 1},
        {"nbf": 4102444800},
    ),
)
def test_scraper_service_jwt_rejects_wrong_or_stale_claims(monkeypatch, mutation):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    values = {**claims(int(time.time())), **mutation}
    token = jwt.encode(values, private_key, algorithm="RS256")
    with pytest.raises(JWTAuthError):
        validator(private_key.public_key(), monkeypatch).validate(token)


def test_scraper_service_jwt_rejects_wrong_signature_and_malformed_token(monkeypatch):
    trusted = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    untrusted = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = validator(trusted.public_key(), monkeypatch)
    token = jwt.encode(claims(int(time.time())), untrusted, algorithm="RS256")
    for candidate in (token, "not-a-jwt"):
        with pytest.raises(JWTAuthError):
            verifier.validate(candidate)
