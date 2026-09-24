"""Deny-by-default CONNECT proxy for the governed ElevenLabs provider."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import ssl
from contextlib import suppress

APPROVED_HOST = "api.elevenlabs.io"
APPROVED_PORT = 443
MAX_HEADER_BYTES = 16 * 1024
BUFFER_BYTES = 64 * 1024

logger = logging.getLogger("codestra.elevenlabs_egress")


def _approved_authority(value: str) -> bool:
    host, separator, port = value.rpartition(":")
    return bool(separator) and host.lower() == APPROVED_HOST and port == "443"


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(BUFFER_BYTES):
            writer.write(data)
            await writer.drain()
    finally:
        with suppress(Exception):
            writer.write_eof()


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    outcome = "rejected"
    try:
        header = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=5.0
        )
        if len(header) > MAX_HEADER_BYTES or b"\x00" in header:
            raise ValueError("invalid proxy request")
        lines = header.decode("ascii", "strict").split("\r\n")
        method, authority, version = lines[0].split(" ", 2)
        if (
            method != "CONNECT"
            or version != "HTTP/1.1"
            or not _approved_authority(authority)
        ):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        upstream_reader, connected_writer = await asyncio.wait_for(
            asyncio.open_connection(APPROVED_HOST, APPROVED_PORT), timeout=10.0
        )
        upstream_writer = connected_writer
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        outcome = "connected"
        downstream = asyncio.create_task(_relay(reader, connected_writer))
        upstream = asyncio.create_task(_relay(upstream_reader, writer))
        done, pending = await asyncio.wait(
            {downstream, upstream}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, UnicodeError):
        pass
    except (ValueError, asyncio.TimeoutError, OSError):
        if not writer.is_closing():
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            with suppress(Exception):
                await writer.drain()
    finally:
        logger.info("elevenlabs_egress_connection outcome=%s", outcome)
        if upstream_writer is not None:
            upstream_writer.close()
            with suppress(Exception):
                await upstream_writer.wait_closed()
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


async def check_upstream() -> None:
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(
        APPROVED_HOST, APPROVED_PORT, type=socket.SOCK_STREAM
    )
    if not addresses:
        raise RuntimeError("approved provider DNS resolution failed")
    context = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            APPROVED_HOST,
            APPROVED_PORT,
            ssl=context,
            server_hostname=APPROVED_HOST,
        ),
        timeout=10.0,
    )
    try:
        writer.write(
            b"GET /v1/user HTTP/1.1\r\n"
            b"Host: api.elevenlabs.io\r\n"
            b"Accept: application/json\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        parts = status_line.decode("ascii", "strict").strip().split(" ", 2)
        if len(parts) < 2 or parts[1] not in {"401", "403"}:
            raise RuntimeError("unexpected unauthenticated provider response")
    finally:
        writer.close()
        await writer.wait_closed()


async def serve() -> None:
    host = os.getenv("ELEVENLABS_EGRESS_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("ELEVENLABS_EGRESS_LISTEN_PORT", "8888"))
    if not 1 <= port <= 65535:
        raise RuntimeError("invalid egress proxy port")
    server = await asyncio.start_server(
        handle_client, host, port, limit=MAX_HEADER_BYTES + 1
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    asyncio.run(check_upstream() if args.check else serve())


if __name__ == "__main__":
    main()
