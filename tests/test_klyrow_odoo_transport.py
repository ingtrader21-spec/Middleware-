import asyncio
import json
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.workers.klyrow_mail_odoo import DeliveryFailure, RestrictedOdooTransport


@pytest.fixture
def configured_transport(tmp_path, monkeypatch):
    key_file = tmp_path / "odoo-api-key"
    key_file.write_text("test-only-service-key")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test private CA")])
    stamp = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(stamp - timedelta(minutes=1))
        .not_valid_after(stamp + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    for key, value in {
        "klyrow_mail_odoo_url": "https://odoo.internal.codestra.agency",
        "klyrow_mail_odoo_database": "test_database",
        "klyrow_mail_odoo_username": "test_service",
        "klyrow_mail_odoo_api_key_file": str(key_file),
        "klyrow_mail_odoo_ca_file": str(ca_file),
    }.items():
        monkeypatch.setattr(settings, key, value)
    return RestrictedOdooTransport()


def test_private_ca_is_used_for_authentication_and_delivery(configured_transport, monkeypatch):
    real_client = httpx.AsyncClient
    requests = []

    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"result": 7 if len(requests) == 1 else {"id": 42}})

    def client(**options):
        context = options["verify"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert len(context.get_ca_certs()) == 1
        assert options["trust_env"] is False
        assert options["follow_redirects"] is False
        return real_client(transport=httpx.MockTransport(handle), **options)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    result = asyncio.run(configured_transport.deliver({"event_id": "test-event"}, "test-key"))
    assert result == {"odoo_record_id": 42}
    assert requests[0]["params"]["method"] == "authenticate"
    assert requests[1]["params"]["args"][3:5] == ["codestra.mail.inbound.event", "ingest_event"]


@pytest.mark.parametrize("ca_value", ["", "/nonexistent/private-ca.pem"])
def test_missing_private_ca_stops_before_credentials_are_sent(configured_transport, monkeypatch, ca_value):
    monkeypatch.setattr(settings, "klyrow_mail_odoo_ca_file", ca_value)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: pytest.fail("network must not start"))
    with pytest.raises(DeliveryFailure, match="odoo_tls_unavailable") as failure:
        asyncio.run(configured_transport.deliver({}, "test-key"))
    assert failure.value.permanent is True


@pytest.mark.parametrize("url", [
    "http://odoo.internal.codestra.agency",
    "https://user:password@odoo.internal.codestra.agency",
    "https://odoo.internal.codestra.agency/other",
    "https://odoo.internal.codestra.agency?other=true",
])
def test_invalid_origin_stops_before_credentials_are_sent(configured_transport, monkeypatch, url):
    monkeypatch.setattr(settings, "klyrow_mail_odoo_url", url)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: pytest.fail("network must not start"))
    with pytest.raises(DeliveryFailure, match="odoo_https_origin_required"):
        asyncio.run(configured_transport.deliver({}, "test-key"))
