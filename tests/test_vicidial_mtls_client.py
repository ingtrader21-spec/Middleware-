import logging
import subprocess
from pathlib import Path
from typing import Callable

import httpx
import pytest
from pydantic import ValidationError

from app.adapters.vicidial.mtls_client import (
    MAX_PAYLOAD_BYTES,
    VicidialMtlsClient,
    VicidialMtlsError,
)
from app.core.config import Settings


AUTH_URL = "https://authorization.internal.codestra.agency:8443"
EDGE_URL = "https://edge.internal.codestra.agency:8443"


def _certificate_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    key = tmp_path / "client.key"
    cert = tmp_path / "client.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=non-production-mtls-test",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, cert, key


def _signed_server_certificate(
    tmp_path: Path, *, hostname: str, expired: bool = False
) -> tuple[Path, Path]:
    ca_key = tmp_path / "ca.key"
    ca_cert = tmp_path / "ca.crt"
    server_key = tmp_path / "server.key"
    server_csr = tmp_path / "server.csr"
    server_cert = tmp_path / "server.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=non-production-test-ca",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={hostname}",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
        ],
        check=True,
        capture_output=True,
    )
    extension = tmp_path / "server.ext"
    extension.write_text(
        f"subjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n"
    )
    if not expired:
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(server_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(extension),
                "-out",
                str(server_cert),
            ],
            check=True,
            capture_output=True,
        )
        return ca_cert, server_cert

    (tmp_path / "index.txt").write_text("")
    (tmp_path / "serial").write_text("1000\n")
    (tmp_path / "newcerts").mkdir()
    ca_config = tmp_path / "ca.cnf"
    ca_config.write_text(
        "[ca]\ndefault_ca=local_ca\n[local_ca]\n"
        f"dir={tmp_path}\ndatabase=$dir/index.txt\nnew_certs_dir=$dir/newcerts\n"
        "certificate=$dir/ca.crt\nprivate_key=$dir/ca.key\nserial=$dir/serial\n"
        "default_md=sha256\ndefault_days=1\npolicy=policy\nx509_extensions=server\n"
        "[policy]\ncommonName=supplied\n[server]\nextendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{hostname}\n"
    )
    subprocess.run(
        [
            "openssl",
            "ca",
            "-batch",
            "-config",
            str(ca_config),
            "-in",
            str(server_csr),
            "-out",
            str(server_cert),
            "-startdate",
            "20200101000000Z",
            "-enddate",
            "20210101000000Z",
        ],
        check=True,
        capture_output=True,
    )
    return ca_cert, server_cert


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    ca, cert, key = _certificate_files(tmp_path)
    values: dict[str, object] = {
        "vicidial_authorization_url": AUTH_URL,
        "vicidial_edge_url": EDGE_URL,
        "vicidial_ca_file": str(ca),
        "vicidial_client_cert_file": str(cert),
        "vicidial_client_key_file": str(key),
        "transfer_control_enabled": True,
        "vicidial_read_enabled": True,
    }
    values.update(overrides)
    # Temporary certificate paths are intentionally limited to tests. Production
    # Settings validation requires /run/secrets/vicidial-mtls.
    return Settings.model_construct(**values)  # type: ignore[arg-type]


def _client(
    settings: Settings,
    handler: Callable[[httpx.Request], httpx.Response],
) -> VicidialMtlsClient:
    return VicidialMtlsClient(
        settings,
        transport_factory=lambda: httpx.MockTransport(handler),
        resolver=lambda _: ["10.42.0.20"],
    )


def test_settings_accept_only_canonical_private_https_urls():
    settings = Settings(
        vicidial_authorization_url=AUTH_URL,
        vicidial_edge_url=EDGE_URL,
    )
    assert settings.vicidial_authorization_url == AUTH_URL
    for invalid in (
        "http://authorization.internal.codestra.agency:8443",
        "https://65.21.67.207:8443",
        "https://authorization.internal.codestra.agency:8095",
        "https://authorization.internal.codestra.agency:8443/unapproved",
        "https://api.codestra.agency:8443",
    ):
        with pytest.raises(ValidationError):
            Settings(vicidial_authorization_url=invalid)


def test_settings_require_secret_mount_paths():
    with pytest.raises(ValidationError):
        Settings(vicidial_ca_file="/tmp/ca.crt")
    settings = Settings(vicidial_ca_file="/run/secrets/vicidial-mtls/ca.crt")
    assert settings.vicidial_ca_file.endswith("/ca.crt")


def test_valid_mtls_request_has_ids_and_exact_route(tmp_path: Path):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"allowed": True})

    client = _client(_settings(tmp_path), handler)
    try:
        assert client.authorize({"lead_id": 42}) == {"allowed": True}
    finally:
        client.close()
    request = captured[0]
    assert request.method == "POST"
    assert request.url.host == "10.42.0.20"
    assert request.url.path == "/api/v1/transfers/authorize"
    assert request.headers["Host"] == ("authorization.internal.codestra.agency:8443")
    assert request.extensions["sni_hostname"] == (
        "authorization.internal.codestra.agency"
    )
    assert request.headers["X-Correlation-ID"]
    assert request.headers["X-Request-ID"]


def test_governed_hostnames_use_distinct_transport_pools(tmp_path: Path) -> None:
    next_pool = 0
    captured: list[tuple[int, httpx.Request]] = []

    def transport_factory() -> httpx.BaseTransport:
        nonlocal next_pool
        pool_id = next_pool
        next_pool += 1

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append((pool_id, request))
            return httpx.Response(200, json={"ok": True})

        return httpx.MockTransport(handler)

    settings = _settings(
        tmp_path,
        vicidial_write_enabled=True,
        live_writes_enabled=True,
    )
    client = VicidialMtlsClient(
        settings,
        transport_factory=transport_factory,
        # Reproduce the dangerous case: both governed names share one IP.
        resolver=lambda _: ["10.42.0.20"],
    )
    try:
        assert client.authorize({}) == {"ok": True}
        assert client.execute({}) == {"ok": True}
    finally:
        client.close()

    pools_by_host = {
        request.headers["Host"]: pool_id for pool_id, request in captured
    }
    assert pools_by_host.keys() == {
        "authorization.internal.codestra.agency:8443",
        "edge.internal.codestra.agency:8443",
    }
    assert len(set(pools_by_host.values())) == 2
    assert {request.url.host for _, request in captured} == {"10.42.0.20"}


def test_missing_client_certificate_fails_closed(tmp_path: Path):
    settings = _settings(
        tmp_path, vicidial_client_cert_file=str(tmp_path / "missing.crt")
    )
    with pytest.raises(VicidialMtlsError, match="client certificate is missing"):
        _client(settings, lambda _: httpx.Response(200))


def test_untrusted_ca_fails_closed(tmp_path: Path):
    invalid_ca = tmp_path / "invalid-ca.crt"
    invalid_ca.write_text("not a certificate")
    settings = _settings(tmp_path, vicidial_ca_file=str(invalid_ca))
    with pytest.raises(VicidialMtlsError, match="invalid or unreadable"):
        _client(settings, lambda _: httpx.Response(200))


def test_wrong_hostname_certificate_is_rejected(tmp_path: Path):
    ca, server = _signed_server_certificate(
        tmp_path, hostname="wrong.internal.codestra.agency"
    )
    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(ca),
            "-verify_hostname",
            "authorization.internal.codestra.agency",
            str(server),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "hostname mismatch" in (result.stdout + result.stderr).lower()


def test_expired_server_certificate_is_rejected(tmp_path: Path):
    ca, server = _signed_server_certificate(
        tmp_path, hostname="authorization.internal.codestra.agency", expired=True
    )
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca), str(server)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "expired" in (result.stdout + result.stderr).lower()


def test_crl_validation_is_fail_closed_when_crl_is_invalid(tmp_path: Path):
    crl = tmp_path / "revoked.crl"
    crl.write_text("invalid CRL")
    settings = _settings(tmp_path, vicidial_crl_file=str(crl))
    with pytest.raises(VicidialMtlsError, match="invalid or unreadable"):
        _client(settings, lambda _: httpx.Response(200))


def test_unapproved_route_and_method_are_rejected(tmp_path: Path):
    client = _client(_settings(tmp_path), lambda _: httpx.Response(200))
    try:
        with pytest.raises(VicidialMtlsError, match="method or route"):
            client.request("GET", f"{AUTH_URL}/api/v1/transfers/authorize", {})
        with pytest.raises(VicidialMtlsError, match="method or route"):
            client.request("POST", f"{AUTH_URL}/health", {})
    finally:
        client.close()


def test_timeout_and_connection_refusal_do_not_retry(tmp_path: Path):
    calls = 0

    def timeout(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectTimeout("test timeout", request=request)

    client = _client(_settings(tmp_path), timeout)
    try:
        with pytest.raises(VicidialMtlsError, match="failed closed"):
            client.authorize({"lead_id": 42})
    finally:
        client.close()
    assert calls == 1

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = _client(_settings(tmp_path), refused)
    try:
        with pytest.raises(VicidialMtlsError, match="failed closed"):
            client.authorize({"lead_id": 42})
    finally:
        client.close()


def test_payload_limit_is_enforced_before_transport(tmp_path: Path):
    client = _client(_settings(tmp_path), lambda _: httpx.Response(200))
    try:
        with pytest.raises(VicidialMtlsError, match="payload exceeds"):
            client.authorize({"secret": "x" * MAX_PAYLOAD_BYTES})
    finally:
        client.close()


def test_logs_do_not_contain_payload_or_credentials(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    marker = "DO-NOT-LOG-THIS-SECRET"
    client = _client(
        _settings(tmp_path),
        lambda _: httpx.Response(200, json={"ok": True}),
    )
    try:
        with caplog.at_level(logging.INFO, logger="codestra.vicidial_mtls"):
            client.authorize({"token": marker})
    finally:
        client.close()
    assert marker not in caplog.text
    assert "client.key" not in caplog.text


def test_disabled_flags_fail_closed_before_network(tmp_path: Path):
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    settings = _settings(
        tmp_path,
        transfer_control_enabled=False,
        vicidial_read_enabled=False,
        vicidial_write_enabled=False,
        live_writes_enabled=False,
        external_dial_enabled=False,
    )
    client = _client(settings, handler)
    try:
        with pytest.raises(VicidialMtlsError, match="authorization is disabled"):
            client.authorize({})
        with pytest.raises(VicidialMtlsError, match="execution is disabled"):
            client.execute({})
        with pytest.raises(VicidialMtlsError, match="origination is disabled"):
            client.originate({})
    finally:
        client.close()
    assert calls == 0


def test_originate_disabled_even_with_write_and_live_flags_alone(tmp_path: Path):
    # external_dial_enabled must ALSO be true -- vicidial_write_enabled and
    # live_writes_enabled alone (e.g. because a transfer feature needs them)
    # must never be sufficient to unlock call origination.
    settings = _settings(
        tmp_path,
        vicidial_write_enabled=True,
        live_writes_enabled=True,
        external_dial_enabled=False,
    )
    client = _client(settings, lambda _: httpx.Response(200))
    try:
        with pytest.raises(VicidialMtlsError, match="origination is disabled"):
            client.originate({"destination": "+15551234567"})
    finally:
        client.close()


def test_originate_valid_request_hits_approved_route(tmp_path: Path):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"accepted": True})

    settings = _settings(
        tmp_path,
        vicidial_write_enabled=True,
        live_writes_enabled=True,
        external_dial_enabled=True,
    )
    client = _client(settings, handler)
    try:
        assert client.originate({"destination": "+15551234567"}) == {
            "accepted": True
        }
    finally:
        client.close()
    request = captured[0]
    assert request.method == "POST"
    assert request.url.path == "/v1/calls/originate"
    assert request.headers["X-Correlation-ID"]
    assert request.headers["X-Request-ID"]


def test_public_or_mixed_dns_resolution_fails_before_network(tmp_path: Path):
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    for addresses in (
        ["65.21.67.207"],
        ["10.42.0.20", "65.21.67.207"],
        ["10.42.0.20", "2001:4860:4860::8888"],
        ["::1"],
        ["fe80::1"],
        ["::ffff:10.42.0.20"],
        [],
    ):
        def resolve(_: str, result: list[str] = addresses) -> list[str]:
            return result

        client = VicidialMtlsClient(
            _settings(tmp_path),
            transport_factory=lambda: httpx.MockTransport(handler),
            resolver=resolve,
        )
        try:
            with pytest.raises(VicidialMtlsError, match="private IP"):
                client.authorize({})
        finally:
            client.close()
    assert calls == 0


@pytest.mark.parametrize("address", ["10.42.0.20", "172.20.0.10", "fd00::20"])
def test_rfc1918_and_ipv6_ula_destinations_are_private(
    tmp_path: Path,
    address: str,
) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"authorized": True})

    client = VicidialMtlsClient(
        _settings(tmp_path),
        transport_factory=lambda: httpx.MockTransport(handler),
        resolver=lambda _: [address],
    )
    try:
        assert client.authorize({}) == {"authorized": True}
    finally:
        client.close()
    assert captured[0].url.host == address
    assert captured[0].headers["Host"] == (
        "authorization.internal.codestra.agency:8443"
    )
    assert captured[0].extensions["sni_hostname"] == (
        "authorization.internal.codestra.agency"
    )


def test_sync_agent_disabled_without_write_and_live_flags(tmp_path: Path):
    settings = _settings(tmp_path, vicidial_write_enabled=False, live_writes_enabled=False)
    client = _client(settings, lambda request: httpx.Response(200, json={}))
    try:
        with pytest.raises(VicidialMtlsError, match="agent sync is disabled"):
            client.sync_agent({"agent": {"user_id": "COD0016"}})
    finally:
        client.close()


def test_sync_agent_valid_request_hits_approved_route(tmp_path: Path):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"user_id": "COD0016", "active": False})

    settings = _settings(tmp_path, vicidial_write_enabled=True, live_writes_enabled=True)
    client = _client(settings, handler)
    try:
        assert client.sync_agent({"agent": {"user_id": "COD0016"}}) == {
            "user_id": "COD0016", "active": False,
        }
    finally:
        client.close()
    request = captured[0]
    assert request.method == "POST"
    assert request.url.path == "/v1/agents/sync"
    assert request.headers["X-Correlation-ID"]
    assert request.headers["X-Request-ID"]


def test_disable_agent_disabled_without_write_and_live_flags(tmp_path: Path):
    settings = _settings(tmp_path, vicidial_write_enabled=False, live_writes_enabled=False)
    client = _client(settings, lambda request: httpx.Response(200, json={}))
    try:
        with pytest.raises(VicidialMtlsError, match="agent disable is disabled"):
            client.disable_agent({"user_id": "COD0016"})
    finally:
        client.close()


def test_disable_agent_valid_request_hits_approved_route(tmp_path: Path):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"user_id": "COD0016", "active": False})

    settings = _settings(tmp_path, vicidial_write_enabled=True, live_writes_enabled=True)
    client = _client(settings, handler)
    try:
        assert client.disable_agent({"user_id": "COD0016"}) == {
            "user_id": "COD0016", "active": False,
        }
    finally:
        client.close()
    request = captured[0]
    assert request.method == "POST"
    assert request.url.path == "/v1/agents/disable"


@pytest.mark.parametrize(
    ("method_name", "match", "path"),
    [
        ("reserve_extension", "extension reservation is disabled", "/v1/extensions/reserve"),
        ("adopt_extension", "extension adoption is disabled", "/v1/extensions/adopt"),
        ("provision_webrtc", "WebRTC provisioning is disabled", "/v1/webrtc/provision"),
        ("rotate_webrtc_secret", "WebRTC credential rotation is disabled", "/v1/webrtc/rotate"),
        ("revoke_webrtc", "WebRTC revocation is disabled", "/v1/webrtc/revoke"),
    ],
)
def test_new_telephony_methods_disabled_without_write_and_live_flags(
    tmp_path: Path, method_name: str, match: str, path: str,
) -> None:
    settings = _settings(tmp_path, vicidial_write_enabled=False, live_writes_enabled=False)
    client = _client(settings, lambda request: httpx.Response(200, json={}))
    try:
        with pytest.raises(VicidialMtlsError, match=match):
            getattr(client, method_name)({})
    finally:
        client.close()


@pytest.mark.parametrize(
    ("method_name", "path"),
    [
        ("reserve_extension", "/v1/extensions/reserve"),
        ("adopt_extension", "/v1/extensions/adopt"),
        ("provision_webrtc", "/v1/webrtc/provision"),
        ("rotate_webrtc_secret", "/v1/webrtc/rotate"),
        ("revoke_webrtc", "/v1/webrtc/revoke"),
    ],
)
def test_new_telephony_methods_valid_request_hits_approved_route(
    tmp_path: Path, method_name: str, path: str,
) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"status": "ok"})

    settings = _settings(tmp_path, vicidial_write_enabled=True, live_writes_enabled=True)
    client = _client(settings, handler)
    try:
        assert getattr(client, method_name)({}) == {"status": "ok"}
    finally:
        client.close()
    request = captured[0]
    assert request.method == "POST"
    assert request.url.path == path
    assert request.headers["X-Correlation-ID"]
    assert request.headers["X-Request-ID"]
