from __future__ import annotations

import base64
from pathlib import Path

import pytest
from pydantic import SecretStr
from starlette.requests import Request

from codestra_connector_runtime.api.config import RuntimeSettings
from codestra_connector_runtime.api.crypto import EncryptedBodyStore
from codestra_connector_runtime.api.cursor import CursorCodec
from codestra_connector_runtime.api.problems import ProblemError
from codestra_connector_runtime.api.repository import _etag_version
from codestra_connector_runtime.api.webhook_ingress import read_limited_body


def test_cursor_is_signed_and_tamper_evident() -> None:
    codec = CursorCodec(b"c" * 32)
    token = codec.encode({"after": "abc"})
    assert codec.decode(token) == {"after": "abc"}
    body, signature = token.split(".", 1)
    replacement = "A" if signature[-1] != "A" else "B"
    with pytest.raises(ProblemError):
        codec.decode(body + "." + signature[:-1] + replacement)


def test_etag_requires_positive_version() -> None:
    assert _etag_version('"v7"') == 7
    assert _etag_version('W/"v3"') == 3
    with pytest.raises(ProblemError):
        _etag_version(None)
    with pytest.raises(ProblemError):
        _etag_version('"v0"')


def test_encrypted_body_store_round_trip(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(base64.b64encode(b"k" * 32))
    store = EncryptedBodyStore.from_key_file(tmp_path / "bodies", key_file)
    body = b'{"event":"example"}'
    reference = store.persist(
        body,
        tenant_id="11111111-1111-4111-8111-111111111111",
        webhook_id="22222222-2222-4222-8222-222222222222",
        event_id="evt-1",
    )
    assert reference.startswith("file:")
    encrypted_path = tmp_path / "bodies" / reference.removeprefix("file:")
    assert body not in encrypted_path.read_bytes()
    assert store.read(
        reference,
        tenant_id="11111111-1111-4111-8111-111111111111",
        webhook_id="22222222-2222-4222-8222-222222222222",
        event_id="evt-1",
        body_sha256=__import__("hashlib").sha256(body).hexdigest(),
    ) == body
    store.remove(reference)
    assert not encrypted_path.exists()


def _streaming_request(
    chunks: list[bytes],
    *,
    content_length: str | None = None,
    disconnect: bool = False,
) -> Request:
    headers = []
    if content_length is not None:
        headers.append((b"content-length", content_length.encode("ascii")))
    messages = [
        {"type": "http.request", "body": chunk, "more_body": True}
        for chunk in chunks
    ]
    messages.append(
        {"type": "http.disconnect"}
        if disconnect
        else {"type": "http.request", "body": b"", "more_body": False}
    )

    async def receive():
        return messages.pop(0)

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/example",
            "headers": headers,
            "scheme": "https",
            "server": ("test", 443),
            "client": ("test", 1234),
            "query_string": b"",
        },
        receive,
    )


@pytest.mark.asyncio
async def test_limited_body_accepts_exact_limit_without_content_length() -> None:
    request = _streaming_request([b"ab", b"cd"])
    assert await read_limited_body(
        request,
        maximum_bytes=4,
        error_code="BODY_TOO_LARGE",
        error_title="Too large",
        error_detail="Too large.",
    ) == b"abcd"


@pytest.mark.asyncio
async def test_limited_body_rejects_misleading_content_length_incrementally() -> None:
    request = _streaming_request([b"abc", b"def"], content_length="1")
    with pytest.raises(ProblemError, match="Too large") as captured:
        await read_limited_body(
            request,
            maximum_bytes=4,
            error_code="BODY_TOO_LARGE",
            error_title="Too large",
            error_detail="Too large.",
        )
    assert captured.value.status == 413


@pytest.mark.asyncio
async def test_limited_body_rejects_declared_oversize_before_streaming() -> None:
    request = _streaming_request([b"a"], content_length="5")
    with pytest.raises(ProblemError) as captured:
        await read_limited_body(
            request,
            maximum_bytes=4,
            error_code="BODY_TOO_LARGE",
            error_title="Too large",
            error_detail="Too large.",
        )
    assert captured.value.status == 413


@pytest.mark.asyncio
async def test_limited_body_rejects_disconnect() -> None:
    request = _streaming_request([b"ab"], disconnect=True)
    with pytest.raises(ProblemError) as captured:
        await read_limited_body(
            request,
            maximum_bytes=4,
            error_code="BODY_TOO_LARGE",
            error_title="Too large",
            error_detail="Too large.",
        )
    assert captured.value.code == "REQUEST_BODY_DISCONNECTED"


def test_settings_are_fail_closed(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(b"x" * 32)
    settings = RuntimeSettings(
        database_url=SecretStr("postgresql+psycopg://example:example@localhost/example"),
        cursor_hmac_key=SecretStr("y" * 32),
        body_encryption_key_file=key_file,
    )
    assert settings.connector_install_enabled is False
    assert settings.webhook_ingress_enabled is False
    assert settings.external_effects_enabled is False
    with pytest.raises(ValueError):
        RuntimeSettings(
            environment="production",
            database_url=SecretStr("postgresql+psycopg://example:example@localhost/example"),
            cursor_hmac_key=SecretStr("y" * 32),
            body_encryption_key_file=key_file,
            connector_activation_enabled=True,
            release_sha="a" * 40,
        )


def test_settings_accept_documented_uppercase_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(b"x" * 32)
    monkeypatch.setenv(
        "CONNECTOR_RUNTIME_DATABASE_URL",
        "postgresql+psycopg://example:example@localhost/example",
    )
    monkeypatch.setenv("CONNECTOR_RUNTIME_CURSOR_HMAC_KEY", "y" * 32)
    monkeypatch.setenv(
        "CONNECTOR_RUNTIME_BODY_ENCRYPTION_KEY_FILE",
        str(key_file),
    )

    settings = RuntimeSettings()  # type: ignore[call-arg]

    assert settings.database_url.get_secret_value().endswith("/example")
    assert settings.body_encryption_key_file == key_file
