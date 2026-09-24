from __future__ import annotations

import hashlib
import hmac
import os
import stat
import time
from pathlib import Path
from typing import Any

import httpx

from .core.config import Settings


class ProvisioningServiceAdapterError(Exception):
    """Raised when a codestra-provisioning-service call cannot be completed."""


def _read_private_secret(path: str, *, minimum_bytes: int = 32) -> bytes:
    """Read an HMAC secret from a mounted file, refusing anything that
    is not an absolute, regular, non-symlinked, mode-0600-or-stricter file.

    Mirrors the equivalent private helper in
    ``app/vicidial_odoo_projection_config_base.py`` rather than importing
    it across module boundaries; the secret is never accepted as a raw
    environment variable value, only as a path reference, consistent
    with every other ``*_hmac_secret_file`` setting in this repo.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ProvisioningServiceAdapterError("secret paths must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ProvisioningServiceAdapterError(
            f"protected file cannot be opened: {candidate}"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProvisioningServiceAdapterError("protected path is not a regular file")
        if info.st_mode & 0o077:
            raise ProvisioningServiceAdapterError(
                "protected file must be mode 0600 or stricter"
            )
        raw = os.read(descriptor, 65537)
    finally:
        os.close(descriptor)
    if len(raw) > 65536:
        raise ProvisioningServiceAdapterError("protected file is too large")
    secret = raw.strip()
    if len(secret) < minimum_bytes:
        raise ProvisioningServiceAdapterError(
            f"secret must be at least {minimum_bytes} bytes"
        )
    return secret


def sign_middleware_invocation(secret: bytes, *, timestamp: str, body: bytes) -> str:
    """Produce the exact signature codestra-provisioning-service's
    ``verify_middleware_invocation`` (app/security.py) checks for:
    ``hmac_sha256(secret, timestamp + "." + body)``, hex-encoded, with
    a ``sha256=`` prefix applied by the caller when building the header.
    """
    canonical = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


class ProvisioningServiceAdapter:
    """Client for codestra-provisioning-service's Middleware-invocation-gated
    provisioning routes (PR #31: every mutating route requires an
    ``X-Middleware-Timestamp``/``X-Middleware-Signature`` attestation on
    top of the existing Keycloak service JWT).

    This adapter exists so the path is *available* once a real business
    need appears; it is deliberately NOT wired into
    ``_run_channel_provisioning_step``'s active dispatch today. As of
    this session's M2 investigation, codestra-provisioning-service has
    zero live callers anywhere in the org, so making it part of the
    saga's live control flow would be an unreviewed behavior change for
    a capability nothing currently needs. Wiring it in is a follow-up
    decision, not something to do silently alongside this adapter.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _require_enabled(self) -> None:
        if not self.settings.provisioning_service_invocation_enabled:
            raise ProvisioningServiceAdapterError(
                "provisioning-service invocation is disabled by "
                "PROVISIONING_SERVICE_INVOCATION_ENABLED"
            )
        if not self.settings.provisioning_service_base_url:
            raise ProvisioningServiceAdapterError(
                "provisioning_service_base_url is not configured"
            )
        if not self.settings.provisioning_service_hmac_secret_file:
            raise ProvisioningServiceAdapterError(
                "provisioning_service_hmac_secret_file is not configured"
            )

    def _attestation_headers(self, body: bytes) -> dict[str, str]:
        secret = _read_private_secret(self.settings.provisioning_service_hmac_secret_file)
        timestamp = str(int(time.time()))
        signature = sign_middleware_invocation(secret, timestamp=timestamp, body=body)
        return {
            "X-Middleware-Timestamp": timestamp,
            "X-Middleware-Signature": f"sha256={signature}",
        }

    async def execute_operation(
        self,
        *,
        request_id: str,
        operation: str,
        payload: dict[str, Any],
        bearer_token: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        """POST /v1/provisioning/requests/{request_id}/execute, attested.

        Not called by the active saga path today -- see class docstring.
        """
        self._require_enabled()
        import json

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
            "X-Correlation-ID": correlation_id,
            **self._attestation_headers(body),
        }
        url = (
            self.settings.provisioning_service_base_url.rstrip("/")
            + f"/v1/provisioning/requests/{request_id}/execute"
        )
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.provisioning_service_timeout_seconds, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(url, content=body, headers=headers)
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProvisioningServiceAdapterError(
                "codestra-provisioning-service execute call failed"
            ) from exc
        if not isinstance(value, dict):
            raise ProvisioningServiceAdapterError(
                "codestra-provisioning-service response is malformed"
            )
        return value
