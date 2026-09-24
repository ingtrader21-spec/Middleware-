from __future__ import annotations

import hashlib
import hmac
import base64
import ipaddress
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.qwen_auth_verifier import AUTH_PATH, IdentityConfig, VerifierConfig, create_app

SERVICE_ID = "qwen-ai-01"
KEY_ID = "qwen-ai-01-hmac-20260804-01"
SERIAL = 12289
URI_SAN = "spiffe://codestra.internal/service/qwen-ai-01"
IP_SAN = "10.40.0.4"
SECRET = b"7f" * 32
UTC = timezone.utc


def issue_certificate(
    directory: Path,
    *,
    serial: int = SERIAL,
    uri: str = URI_SAN,
    ip_san: str = IP_SAN,
    client_auth: bool = True,
    digital_signature: bool = True,
    trusted: bool = True,
    service_id: str = SERVICE_ID,
) -> tuple[Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    signer_key = ca_key if trusted else ec.generate_private_key(ec.SECP256R1())
    signer_name = ca_name if trusted else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-ca")]
    )
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Codestra"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI Agents"),
                    x509.NameAttribute(NameOID.COMMON_NAME, service_id),
                ]
            )
        )
        .issuer_name(signer_name)
        .public_key(client_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(ip_san)),
                x509.UniformResourceIdentifier(uri),
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(digital_signature, False, False, False, False, False, False, False, False),
            critical=True,
        )
    )
    if client_auth:
        client_builder = client_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
        )
    client = client_builder.sign(signer_key, hashes.SHA256())
    ca_file = directory / "client-ca.crt"
    ca_file.write_bytes(ca.public_bytes(Encoding.PEM))
    return ca_file, base64.b64encode(client.public_bytes(Encoding.DER)).decode("ascii")


@pytest.fixture
def verifier(tmp_path: Path) -> tuple[TestClient, VerifierConfig, str]:
    secret = tmp_path / "hmac"
    secret.write_bytes(SECRET)
    secret.chmod(0o600)
    replay = tmp_path / "replay"
    replay.mkdir(mode=0o700)
    ca_file, certificate = issue_certificate(tmp_path)
    config = VerifierConfig(
        service_id=SERVICE_ID,
        hmac_key_id=KEY_ID,
        hmac_secret_file=secret,
        client_ca_file=ca_file,
        certificate_serial=SERIAL,
        certificate_uri_san=URI_SAN,
        certificate_ip_san=ipaddress.IPv4Address(IP_SAN),
        replay_directory=replay,
        trusted_proxy_network=__import__("ipaddress").ip_network("172.18.0.0/16"),
        allowed_clock_skew_seconds=300,
    )
    return TestClient(create_app(config), client=("172.18.0.7", 443)), config, certificate


def signed_headers(
    certificate: str,
    *,
    body: bytes = b"{}",
    method: str = "POST",
    path: str = AUTH_PATH,
    service_id: str = SERVICE_ID,
    key_id: str = KEY_ID,
    timestamp: str | None = None,
    nonce: str = "nonce-0123456789abcdef",
    digest: str | None = None,
    signature: str | None = None,
) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    digest = digest or hashlib.sha256(body).hexdigest()
    canonical = (
        f"{method}\n{path}\n{service_id}\n{timestamp}\n{nonce}\n{digest}"
    ).encode()
    signature = signature or hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
    return {
        "X-Service-ID": service_id,
        "X-HMAC-Key-ID": key_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Body-SHA256": digest,
        "X-Signature": signature,
        "X-Correlation-ID": "correlation-qwen-0001",
        "X-Codestra-Client-Certificate-DER": certificate,
        "Content-Type": "application/json",
    }


def test_valid_request_and_response_contract(verifier):
    client, _, certificate = verifier
    response = client.post(AUTH_PATH, content=b"{}", headers=signed_headers(certificate))
    assert response.status_code == 200
    assert set(response.json()) == {
        "authentication_status",
        "correlation_id",
        "server_timestamp",
    }
    assert response.json()["authentication_status"] == "authenticated"


def test_durable_replay_survives_new_application_instance(verifier):
    client, config, certificate = verifier
    headers = signed_headers(certificate, nonce="durable-replay-00000001")
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 200
    restarted = TestClient(create_app(config), client=("172.18.0.7", 443))
    assert restarted.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 409


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"X-Service-ID": "other"}, 401),
        ({"X-HMAC-Key-ID": "other"}, 401),
        ({"X-Timestamp": "not-a-timestamp"}, 401),
        ({"X-Timestamp": str(int(time.time()) - 301)}, 401),
        ({"X-Timestamp": str(int(time.time()) + 301)}, 401),
        ({"X-Nonce": "short"}, 401),
        ({"X-Body-SHA256": "0" * 64}, 401),
        ({"X-Signature": "0" * 64}, 401),
    ],
)
def test_negative_hmac_inputs(verifier, mutation, expected):
    client, _, certificate = verifier
    headers = signed_headers(certificate, nonce=f"negative-{hash(str(mutation)) & 0xffffffff:08x}-nonce")
    headers.update(mutation)
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == expected


def test_missing_certificate_rejected(verifier):
    client, _, certificate = verifier
    headers = signed_headers(certificate)
    del headers["X-Codestra-Client-Certificate-DER"]
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 422


@pytest.mark.parametrize("value", ["", "%%%not-base64%%%", base64.b64encode(b"not-der").decode(), "A" * 20000])
def test_malformed_empty_or_oversized_der_rejected(verifier, value):
    client, _, certificate = verifier
    headers = signed_headers(certificate, nonce=f"malformed-{len(value):05d}-nonce")
    headers["X-Codestra-Client-Certificate-DER"] = value
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code in {401, 422}


def test_legacy_pem_header_is_rejected(verifier):
    client, _, certificate = verifier
    headers = signed_headers(certificate, nonce="legacy-pem-rejected-0001")
    headers["X-Codestra-Client-Certificate"] = "client-controlled"
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 401


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ip_san": "10.40.0.5"},
        {"client_auth": False},
        {"digital_signature": False},
    ],
)
def test_wrong_ip_eku_or_key_usage_rejected(verifier, tmp_path, kwargs):
    client, _, _ = verifier
    _, certificate = issue_certificate(tmp_path / str(len(str(kwargs))), **kwargs)
    headers = signed_headers(certificate, nonce=f"extension-{len(str(kwargs)):04d}-nonce")
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 401


@pytest.mark.parametrize(
    ("serial", "uri", "trusted"),
    [(12290, URI_SAN, True), (SERIAL, "spiffe://codestra.internal/service/other", True), (SERIAL, URI_SAN, False)],
)
def test_wrong_or_untrusted_certificate_rejected(verifier, tmp_path, serial, uri, trusted):
    client, _, _ = verifier
    _, certificate = issue_certificate(tmp_path / f"cert-{serial}-{trusted}", serial=serial, uri=uri, trusted=trusted)
    headers = signed_headers(certificate, nonce=f"certificate-{serial}-{trusted}-nonce")
    assert client.post(AUTH_PATH, content=b"{}", headers=headers).status_code == 401


def test_public_or_wrong_source_rejected(verifier):
    _, config, certificate = verifier
    public = TestClient(create_app(config), client=("198.51.100.10", 443))
    assert public.post(AUTH_PATH, content=b"{}", headers=signed_headers(certificate)).status_code == 401


def test_incorrect_signed_method_path_and_body_rejected(verifier):
    client, _, certificate = verifier
    assert client.post(AUTH_PATH, content=b"{}", headers=signed_headers(certificate, method="GET")).status_code == 401
    assert client.post(AUTH_PATH, content=b"{}", headers=signed_headers(certificate, path="/wrong")).status_code == 401
    assert client.post(AUTH_PATH, content=b'{"changed":true}', headers=signed_headers(certificate)).status_code == 401


def test_unsupported_methods_routes_and_no_downstream_surface(verifier):
    client, _, certificate = verifier
    assert client.get(AUTH_PATH, headers=signed_headers(certificate, method="GET")).status_code == 405
    assert client.post("/internal/api/v1/ai/commands", content=b"{}", headers=signed_headers(certificate)).status_code == 404
    paths = {route.path for route in client.app.routes}
    assert paths == {"/openapi.json", "/healthz", "/readyz", AUTH_PATH}


def test_multi_identity_v2_and_v1_backward_compatibility(verifier, tmp_path):
    legacy_client, config, legacy_certificate = verifier
    worker_secret = tmp_path / "worker-hmac"
    worker_secret.write_bytes(b"9a" * 32)
    worker_secret.chmod(0o600)
    worker_serial = 12345
    worker_uri = "spiffe://codestra.internal/service/qwen-polling-worker"
    worker_ca, worker_certificate = issue_certificate(
        tmp_path / "worker-cert", serial=worker_serial, uri=worker_uri,
        service_id="qwen-polling-worker",
    )
    configured = VerifierConfig(
        **{**config.__dict__, "client_ca_file": worker_ca, "additional_identities": (IdentityConfig(
            "qwen-polling-worker", "qwen-polling-worker-hmac-v1", worker_secret,
            worker_serial, worker_uri, ipaddress.IPv4Address(IP_SAN),
        ),)}
    )
    client = TestClient(create_app(configured), client=("172.18.0.7", 443))
    assert legacy_client.post(AUTH_PATH, content=b"{}", headers=signed_headers(
        legacy_certificate, nonce="legacy-still-valid-0001"
    )).status_code == 200

    body = b"{}"
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    nonce = "worker-v2-nonce-000001"
    request_id = "request-worker-0001"
    correlation = "correlation-worker-0001"
    worker_id = "qwen-worker-01"
    canonical = "\n".join(("POST", AUTH_PATH, timestamp, nonce, digest,
                            request_id, correlation, worker_id)).encode("ascii")
    headers = {
        "X-Service-ID": "qwen-polling-worker",
        "X-HMAC-Key-ID": "qwen-polling-worker-hmac-v1",
        "X-Timestamp": timestamp, "X-Nonce": nonce, "X-Body-SHA256": digest,
        "X-Signature": hmac.new(b"9a" * 32, canonical, hashlib.sha256).hexdigest(),
        "X-Correlation-ID": correlation, "X-Request-ID": request_id,
        "X-Worker-ID": worker_id, "X-Signature-Version": "v2",
        "X-Codestra-Client-Certificate-DER": worker_certificate,
    }
    assert client.post(AUTH_PATH, content=body, headers=headers).status_code == 200
    assert client.post(AUTH_PATH, content=body, headers=headers).status_code == 409
