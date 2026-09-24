from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import UTC, datetime


class AuthenticationError(PermissionError):
    pass


@dataclass(frozen=True)
class ExporterIdentity:
    certificate_identity: str
    environment: str
    role: str
    audience: str
    certificate_not_after: datetime | None = None
    certificate_revoked: bool = False


class ReplayGuard:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def consume(self, nonce: str, timestamp: int, now: int | None = None) -> None:
        current = now if now is not None else int(time.time())
        if not nonce or abs(current - timestamp) > self.ttl_seconds:
            raise AuthenticationError("stale or missing replay binding")
        self._seen = {
            key: expires for key, expires in self._seen.items() if expires > current
        }
        fingerprint = hashlib.sha256(nonce.encode()).hexdigest()
        if fingerprint in self._seen:
            raise AuthenticationError("request replay rejected")
        self._seen[fingerprint] = current + self.ttl_seconds


class MTLSAuthorizer:
    """Fail-closed identity mapping performed after TLS terminates privately."""

    def __init__(
        self,
        mappings: dict[str, str],
        audience: str = "codestra-recording-api",
        role: str = "recording-exporter",
    ) -> None:
        self.mappings = mappings
        self.audience = audience
        self.role = role

    def authorize(self, identity: ExporterIdentity) -> None:
        expected_environment = self.mappings.get(identity.certificate_identity)
        now = datetime.now(UTC)
        if (
            expected_environment is None
            or not hmac.compare_digest(expected_environment, identity.environment)
            or not hmac.compare_digest(identity.role, self.role)
            or not hmac.compare_digest(identity.audience, self.audience)
            or identity.certificate_not_after is None
            or identity.certificate_not_after <= now
            or identity.certificate_revoked
        ):
            raise AuthenticationError("exporter mTLS binding rejected")
