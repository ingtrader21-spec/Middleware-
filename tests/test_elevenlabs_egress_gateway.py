from __future__ import annotations

import asyncio
import ipaddress
from unittest.mock import AsyncMock

import pytest

from app.entrypoints import elevenlabs_egress_gateway as gateway


def test_authority_is_exact_and_fail_closed() -> None:
    assert gateway._approved_authority("api.elevenlabs.io:443")
    assert gateway._approved_authority("API.ELEVENLABS.IO:443")
    assert not gateway._approved_authority("api.elevenlabs.io:80")
    assert not gateway._approved_authority("example.com:443")
    assert not gateway._approved_authority("api.elevenlabs.io.evil:443")
    assert not gateway._approved_authority("api.elevenlabs.io:443@evil:443")


def test_health_probe_contains_no_credential_material() -> None:
    source = open(
        "app/entrypoints/elevenlabs_egress_gateway.py", encoding="utf-8"
    ).read()
    assert "GET /v1/user HTTP/1.1" in source
    assert 'parts[1] not in {"401", "403"}' in source
    assert "xi-api-key" not in source
    assert "Authorization:" not in source


class Writer:
    def __init__(self) -> None:
        self.output = bytearray()
        self.closed = False

    def write(self, value: bytes) -> None:
        self.output.extend(value)

    async def drain(self) -> None:
        return None

    def is_closing(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.mark.asyncio
async def test_unapproved_destination_is_denied_without_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    reader.feed_eof()
    writer = Writer()
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)

    await gateway.handle_client(reader, writer)  # type: ignore[arg-type]

    assert bytes(writer.output).startswith(b"HTTP/1.1 403 Forbidden")
    connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_connect_method_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"GET http://api.elevenlabs.io/ HTTP/1.1\r\n\r\n")
    reader.feed_eof()
    writer = Writer()
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)

    await gateway.handle_client(reader, writer)  # type: ignore[arg-type]

    assert bytes(writer.output).startswith(b"HTTP/1.1 403 Forbidden")
    connect.assert_not_awaited()


def test_overlay_preserves_internal_controller_boundary() -> None:
    source = open(
        "deploy/elevenlabs-egress/compose.overlay.yaml", encoding="utf-8"
    ).read()
    assert "network_mode: host" not in source
    assert "ports:" not in source
    assert "elevenlabs_proxy:\n    internal: true" in source
    assert "api-key" not in source
    assert "xi-api-key" not in source


def test_explicit_ipam_is_small_and_non_overlapping() -> None:
    proxy = ipaddress.ip_network("10.254.41.0/29")
    egress = ipaddress.ip_network("10.254.41.8/29")
    reserved = (
        ipaddress.ip_network("10.40.0.0/24"),
        ipaddress.ip_network("10.250.240.0/28"),
        ipaddress.ip_network("10.250.241.0/29"),
        ipaddress.ip_network("10.254.40.0/28"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    assert proxy.num_addresses == 8
    assert egress.num_addresses == 8
    assert not proxy.overlaps(egress)
    assert all(not candidate.overlaps(item) for candidate in (proxy, egress) for item in reserved)

    source = open(
        "deploy/elevenlabs-egress/compose.overlay.yaml", encoding="utf-8"
    ).read()
    assert "subnet: 10.254.41.0/29" in source
    assert "gateway: 10.254.41.1" in source
    assert "subnet: 10.254.41.8/29" in source
    assert "gateway: 10.254.41.9" in source
