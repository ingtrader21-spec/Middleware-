"""Offline characterization of certification defects; passing means gap reproduced.

These tests deliberately record current unsafe behavior, not security acceptance.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.application import AppProfile, create_app
from app.db.session import get_session
from app.email.security import TokenValidator


@pytest.mark.parametrize('method,path', [
    ('GET', '/api/v1/commands/CMD-FOREIGN'),
    ('GET', '/api/v1/telephony/commands/CMD-FOREIGN'),
    ('POST', '/api/v1/telephony/commands/CMD-FOREIGN/cancel'),
])
def test_shared_bearer_reaches_unscoped_legacy_command(test_settings, runtime, method, path):
    test_settings.middleware_secret = 'review-only-synthetic-shared-bearer'
    row = SimpleNamespace(command_id=uuid4(), command_public_id='CMD-FOREIGN',
                          command_type='review.synthetic', aggregate_public_id='FOREIGN-RESOURCE',
                          aggregate_version=1, state='QUEUED', correlation_id='foreign-correlation')
    db = AsyncMock()
    db.scalar.return_value = row
    async def session():
        yield db
    app = create_app(settings=test_settings, runtime=runtime, profile=AppProfile.INTEGRATION)
    app.dependency_overrides[get_session] = session
    with TestClient(app) as client:
        denied = client.request(method, path)
        assert denied.status_code == 401
        db.scalar.assert_not_awaited()
        response = client.request(method, path, headers={
            'Authorization': 'Bearer review-only-synthetic-shared-bearer',
            'X-Tenant-ID': 'unrelated-tenant',
        })
    assert response.status_code == 200
    assert response.json()['aggregate_public_id'] == 'FOREIGN-RESOURCE'
    query = str(db.scalar.await_args.args[0])
    assert 'tenant' not in query.lower()
    if method == 'POST':
        assert row.state == 'CANCELLED'
        db.commit.assert_awaited_once()


@pytest.mark.parametrize('tenant', ['tenant-review', None, ['tenant-review']])
def test_email_validator_accepts_no_expiry_and_coerces_tenant(monkeypatch, tenant):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(jwt, 'PyJWKClient', lambda *_a, **_k: SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=private.public_key())))
    claims = {'iss': 'https://identity.example.invalid/review', 'aud': 'codestra-email',
              'sub': 'review-subject', 'azp': 'beyvra-email-production', 'service': 'beyvra',
              'environment': 'production', 'scope': 'email.send', 'tenant_id': tenant}
    token = jwt.encode(claims, private, algorithm='RS256')
    validator = TokenValidator(claims['iss'], claims['aud'], claims['iss'] + '/certs')
    principal = validator.validate(token, 'email.send')
    assert principal.tenant_id == str(tenant)
    assert 'exp' not in claims and 'iat' not in claims


def test_machine_verifier_reuses_removed_signing_key(monkeypatch, test_settings):
    import json
    import time
    from unittest.mock import Mock
    from app.security import KeycloakJwtVerifier

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = KeycloakJwtVerifier(test_settings)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update(kid='review-revoked-key', use='sig', alg='RS256')
    fetch = Mock(return_value={'keys': [public]})
    monkeypatch.setattr(verifier._jwks, 'fetch_data', fetch)
    now = int(time.time())
    claims = {'iss': test_settings.issuer, 'aud': test_settings.audience,
              'sub': 'review-subject', 'azp': 'middleware-api', 'jti': 'review-jti',
              'iat': now, 'exp': now + 120, 'scope': 'platform.command'}
    token = jwt.encode(claims, private, algorithm='RS256', headers={'kid': public['kid']})
    verifier._verify_sync(token, expected_client_id='middleware-api', required_scope='platform.command')
    fetch.assert_called_once()
    # Remove the key from the authoritative set and invalidate the entire set cache.
    # Per-key LRU still wins; no TTL expiration of the set can invalidate this key.
    verifier._jwks.jwk_set_cache.put(None)
    fetch.return_value = {'keys': []}
    claims['jti'] = 'review-fresh-jti'
    fresh = jwt.encode(claims, private, algorithm='RS256', headers={'kid': public['kid']})
    verified = verifier._verify_sync(fresh, expected_client_id='middleware-api', required_scope='platform.command')
    assert verified['jti'] == 'review-fresh-jti'
    fetch.assert_called_once()
