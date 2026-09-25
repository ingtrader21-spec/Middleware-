from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.email.security import AuthorizationError, TokenValidator


ISSUER = "https://identity.example.invalid/review"
AUDIENCE = "codestra-email"


def _validator(monkeypatch, private):
    monkeypatch.setattr(
        jwt,
        "PyJWKClient",
        lambda *_a, **_k: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=private.public_key())
        ),
    )
    return TokenValidator(ISSUER, AUDIENCE, ISSUER + "/certs")


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "review-subject",
        "azp": "beyvra-email-production",
        "service": "beyvra",
        "environment": "production",
        "scope": "email.send",
        "tenant_id": "tenant-review",
        "jti": "email-token-review-1",
        "iat": now,
        "exp": now + 120,
    }
    claims.update(overrides)
    return claims


def _token(private, claims):
    return jwt.encode(claims, private, algorithm="RS256")


def test_email_validator_accepts_bounded_machine_token(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    principal = _validator(monkeypatch, private).validate(
        _token(private, _claims()), "email.send"
    )
    assert principal.subject == "review-subject"
    assert principal.tenant_id == "tenant-review"


@pytest.mark.parametrize("missing", ["exp", "iat", "jti"])
def test_email_validator_requires_machine_timestamps(monkeypatch, missing):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = _claims()
    claims.pop(missing)
    with pytest.raises(AuthorizationError, match="invalid_token"):
        _validator(monkeypatch, private).validate(_token(private, claims), "email.send")


@pytest.mark.parametrize(
    "overrides",
    [
        {"iat": True},
        {"exp": True},
        {"iat": 200, "exp": 199},
        {"iat": 100, "exp": 401},
    ],
)
def test_email_validator_rejects_invalid_machine_lifetime(monkeypatch, overrides):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="invalid_token_lifetime|invalid_token"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(**overrides)), "email.send"
        )


@pytest.mark.parametrize("tenant", [None, "", "   ", ["tenant-review"], "*"])
def test_email_validator_rejects_malformed_tenant(monkeypatch, tenant):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="tenant_required|invalid_token"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(tenant_id=tenant)), "email.send"
        )


@pytest.mark.parametrize("subject", [None, "", "   ", ["review-subject"]])
def test_email_validator_rejects_malformed_subject(monkeypatch, subject):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="invalid_subject|invalid_token"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(sub=subject)), "email.send"
        )


def test_email_validator_rejects_non_string_scope(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="invalid_scope"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(scope=["email.send"])), "email.send"
        )


@pytest.mark.parametrize("jti", [None, "", "   ", ["token-id"]])
def test_email_validator_rejects_malformed_jti(monkeypatch, jti):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="invalid_token_id|invalid_token"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(jti=jti)), "email.send"
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"iat": 10**1000, "exp": 10**1000 + 120},
        {"iat": -(10**1000), "exp": -(10**1000) + 120},
    ],
)
def test_email_validator_rejects_oversized_machine_timestamps(monkeypatch, overrides):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthorizationError, match="invalid_token_lifetime|invalid_token"):
        _validator(monkeypatch, private).validate(
            _token(private, _claims(**overrides)), "email.send"
        )
