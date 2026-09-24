import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.core.config import settings
from app.entrypoints.event_gateway import app

PATH = "/api/v1/readiness/server-a/challenge"
KEY_ID = "vicidial-server-b-readiness"
SECRET = "fixture-secret-that-is-at-least-thirty-two-bytes"


class FakeRedis:
    seen: set[str] = set()
    unavailable = False

    @classmethod
    def from_url(cls, *_args, **_kwargs):
        return cls()

    async def set(self, key, _value, *, ex, nx):
        assert ex == 60 and nx is True
        if self.unavailable:
            raise ConnectionError("fixture unavailable")
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    async def aclose(self):
        return None


def certificate_der(common_name="vicidial-server-b-publisher"):
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .sign(key, algorithm=None)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def canonical(request_id, timestamp, nonce, body=b"{}"):
    return "\n".join(
        (
            "HMAC-V1", "POST", PATH, timestamp, nonce, request_id, KEY_ID,
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()


@pytest.fixture(autouse=True)
def configured(monkeypatch, tmp_path: Path):
    der = certificate_der()
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({KEY_ID: SECRET}))
    key_file.chmod(0o600)
    monkeypatch.setattr(settings, "publisher_hmac_keys_file", str(key_file))
    monkeypatch.setattr(settings, "readiness_publisher_key_id", KEY_ID)
    monkeypatch.setattr(
        settings, "readiness_publisher_cert_sha256",
        x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()).hex(),
    )
    monkeypatch.setattr(settings, "deployed_source_sha", "a" * 40)
    monkeypatch.setattr(settings, "runtime_artifact_checksum", "sha256:" + "b" * 64)
    # The handler borrows the process-wide Redis client from the application
    # state (app.core.providers.get_redis_client); inject the fake there.
    monkeypatch.setattr(app.state, "redis", FakeRedis(), raising=False)
    FakeRedis.seen.clear()
    FakeRedis.unavailable = False
    app.state.request_guard.reset_rate_limits()
    yield der
    app.state.request_guard.reset_rate_limits()


def headers(der, *, nonce="nonce-0123456789abcdef", timestamp=None, source="10.40.0.2", key_id=KEY_ID):
    request_id = "request-0123456789abcdef"
    timestamp = timestamp or str(int(time.time()))
    material = canonical(request_id, timestamp, nonce)
    return {
        "X-Codestra-Verified-Source-IP": source,
        "X-Codestra-Client-Certificate-DER": base64.b64encode(der).decode(),
        "X-Codestra-Request-ID": request_id,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Key-ID": key_id,
        "X-Codestra-Signature": hmac.new(SECRET.encode(), material, hashlib.sha256).hexdigest(),
        "Content-Type": "application/json",
    }


def test_valid_challenge_is_read_only_and_signed(configured):
    result = TestClient(app).post(PATH, content=b"{}", headers=headers(configured))
    assert result.status_code == 200
    assert result.json()["fail_closed"] is True
    assert result.json()["source_sha"] == "a" * 40
    assert result.headers["cache-control"] == "no-store"
    assert len(result.headers["x-codestra-response-signature"]) == 64


@pytest.mark.parametrize("mutation", ["source", "certificate", "identity", "signature", "expired", "future"])
def test_identity_signature_source_and_timestamp_rejections(configured, mutation):
    der = configured
    timestamp = str(int(time.time()))
    values = headers(der, timestamp=timestamp)
    if mutation == "source":
        values["X-Codestra-Verified-Source-IP"] = "10.40.0.99"
    elif mutation == "certificate":
        values["X-Codestra-Client-Certificate-DER"] = base64.b64encode(certificate_der("wrong")).decode()
    elif mutation == "identity":
        values["X-Codestra-Key-ID"] = "wrong-server-b-identity"
    elif mutation == "signature":
        values["X-Codestra-Signature"] = "0" * 64
    elif mutation == "expired":
        values = headers(der, timestamp=str(int(time.time()) - 61))
    elif mutation == "future":
        values = headers(der, timestamp=str(int(time.time()) + 7))
    assert TestClient(app).post(PATH, content=b"{}", headers=values).status_code in (401, 403)


def test_missing_certificate_replay_and_redis_failure_fail_closed(configured):
    values = headers(configured)
    values.pop("X-Codestra-Client-Certificate-DER")
    assert TestClient(app).post(PATH, content=b"{}", headers=values).status_code == 401
    values = headers(configured)
    assert TestClient(app).post(PATH, content=b"{}", headers=values).status_code == 200
    assert TestClient(app).post(PATH, content=b"{}", headers=values).status_code == 401
    FakeRedis.unavailable = True
    assert TestClient(app).post(PATH, content=b"{}", headers=headers(configured, nonce="nonce-unavailable-012345")).status_code == 503


def test_body_size_rate_limit_and_closed_flags(configured, monkeypatch):
    assert TestClient(app).post(PATH, content=b"x" * 4097, headers=headers(configured)).status_code == 413
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    result = TestClient(app).post(PATH, content=b"{}", headers=headers(configured, nonce="nonce-open-flag-01234567"))
    assert result.status_code == 503


def test_proxy_contract_is_private_mtls_and_publicly_denied():
    private = Path("deploy/readiness/Caddyfile.private-vicidial-ingress").read_text()
    public = Path("deploy/readiness/Caddyfile.public-denial.snippet").read_text()
    assert "remote_ip 10.40.0.2" in private
    assert "certificate_der_base64" in private
    assert "max_size 4KB" in private
    assert "reverse_proxy middleware-event-gateway:8095" in private
    assert PATH in private and PATH in public
    assert "respond @private_readiness_on_public 404" in public


def test_existing_event_ingress_contract_is_unchanged():
    paths = app.openapi()["paths"]
    assert "/api/v1/events/vicidial" in paths
    assert PATH in paths
    assert paths[PATH]["post"]["tags"] == ["readiness-challenge"]
