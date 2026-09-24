"""Non-mutating Server B to Server A readiness challenge."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, HTTPException, Request, Response

from app.core.config import settings
from app.core.providers import get_redis_client

router = APIRouter(prefix="/api/v1/readiness", tags=["readiness-challenge"])
PATH = "/api/v1/readiness/server-a/challenge"
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _reject(detail: str, status_code: int = 401) -> None:
    raise HTTPException(status_code, detail)


def _publisher_keys() -> dict[str, str]:
    path = settings._protected_secret_path(
        settings.publisher_hmac_keys_file, "publisher HMAC keys"
    )
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("publisher authentication is unavailable") from exc
    if not isinstance(value, dict):
        raise RuntimeError("publisher authentication is unavailable")
    return {str(key): str(secret) for key, secret in value.items()}


def _certificate_fingerprint(encoded_der: str) -> str:
    try:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(encoded_der, validate=True)
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(401, "verified client certificate is required") from exc
    now = datetime.now(timezone.utc)
    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
        _reject("verified client certificate is invalid", 403)
    return certificate.fingerprint(hashes.SHA256()).hex()


def _canonical(
    request_id: str, timestamp: str, nonce: str, key_id: str, body: bytes
) -> bytes:
    return "\n".join(
        (
            "HMAC-V1",
            "POST",
            PATH,
            timestamp,
            nonce,
            request_id,
            key_id,
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()


def _flag_state() -> dict[str, bool]:
    return {
        "live_writes_enabled": settings.live_writes_enabled,
        "odoo_write_enabled": settings.odoo_write_enabled,
        "odoo_delivery_enabled": settings.odoo_delivery_enabled,
        "n8n_delivery_enabled": settings.n8n_delivery_enabled,
        "n8n_event_delivery_enabled": settings.n8n_event_delivery_enabled,
        "external_delivery_enabled": settings.enable_external_delivery,
        "messaging_enabled": settings.messaging_enabled,
        "external_dial_enabled": settings.external_dial_enabled,
        "callback_dispatch_enabled": settings.callback_dispatch_enabled,
        "vicidial_write_enabled": settings.vicidial_write_enabled,
    }


@router.post("/server-a/challenge")
async def server_a_challenge(request: Request, response: Response) -> dict[str, object]:
    body = await request.body()
    if len(body) > settings.readiness_request_max_bytes:
        _reject("request too large", 413)
    if body not in (b"", b"{}"):
        _reject("readiness challenge body must be empty", 400)
    if request.headers.get("X-Codestra-Verified-Source-IP", "") != settings.readiness_approved_source_ip:
        _reject("source is not authorized", 403)
    fingerprint = _certificate_fingerprint(
        request.headers.get("X-Codestra-Client-Certificate-DER", "")
    )
    if not hmac.compare_digest(fingerprint, settings.readiness_publisher_cert_sha256):
        _reject("publisher certificate identity is not authorized", 403)

    request_id = request.headers.get("X-Codestra-Request-ID", "")
    nonce = request.headers.get("X-Codestra-Nonce", "")
    timestamp = request.headers.get("X-Codestra-Timestamp", "")
    key_id = request.headers.get("X-Codestra-Key-ID", "")
    signature = request.headers.get("X-Codestra-Signature", "")
    if not TOKEN_RE.fullmatch(request_id) or not TOKEN_RE.fullmatch(nonce):
        _reject("request binding is invalid")
    if key_id != settings.readiness_publisher_key_id:
        _reject("publisher identity is not authorized", 403)
    try:
        signed_at = int(timestamp)
    except ValueError:
        _reject("timestamp is invalid")
    now = int(time.time())
    if signed_at > now + settings.readiness_clock_skew_seconds:
        _reject("timestamp is in the future")
    if signed_at < now - settings.readiness_ttl_seconds:
        _reject("timestamp is expired")
    secret = _publisher_keys().get(key_id, "")
    expected = hmac.new(
        secret.encode(), _canonical(request_id, timestamp, nonce, key_id, body), hashlib.sha256
    ).hexdigest()
    if not secret or not hmac.compare_digest(signature, expected):
        _reject("signature is invalid")

    redis = get_redis_client(request)
    replay_key = "codestra:readiness:nonce:" + hashlib.sha256(
        f"{key_id}:{nonce}".encode()
    ).hexdigest()
    try:
        accepted = await redis.set(replay_key, request_id, ex=settings.readiness_ttl_seconds, nx=True)
    except Exception as exc:
        raise HTTPException(503, "replay protection is unavailable") from exc
    if not accepted:
        _reject("request replay rejected")

    flags = _flag_state()
    if any(flags.values()):
        raise HTTPException(503, "production safety flags are not closed")
    if not SHA_RE.fullmatch(settings.deployed_source_sha):
        raise HTTPException(503, "deployed source identity is unavailable")
    if not DIGEST_RE.fullmatch(settings.runtime_artifact_checksum):
        raise HTTPException(503, "runtime artifact identity is unavailable")
    result: dict[str, object] = {
        "schema_version": "1.0",
        "request_id": request_id,
        "server_identity": settings.readiness_server_identity,
        "source_sha": settings.deployed_source_sha,
        "runtime_checksum": settings.runtime_artifact_checksum,
        "health": {"application": "ready", "redis": "ready"},
        "fail_closed": True,
        "flags": flags,
        "responded_at": datetime.now(timezone.utc).isoformat(),
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    response.headers["X-Codestra-Response-Signature"] = hmac.new(
        secret.encode(), encoded, hashlib.sha256
    ).hexdigest()
    response.headers["Cache-Control"] = "no-store"
    return result
