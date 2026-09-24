from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


class ScraperAuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class ScraperIdentity:
    scraper_id: str
    tenant_id: str
    campaigns: frozenset[str]
    key_id: str
    secret: bytes


class NonceLedger:
    def __init__(self) -> None:
        self._values: set[tuple[str, str]] = set()

    def consume(self, scraper_id: str, nonce: str) -> None:
        key = (scraper_id, nonce)
        if key in self._values:
            raise ScraperAuthenticationError("REPLAYED_NONCE")
        self._values.add(key)


def signature(
    *,
    identity: ScraperIdentity,
    tenant_id: str,
    campaign_id: str,
    request_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    version: str = "hmac-sha256-v2",
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        [
            version,
            identity.key_id,
            identity.scraper_id,
            tenant_id,
            campaign_id,
            request_id,
            timestamp,
            nonce,
            digest,
        ]
    ).encode()
    return hmac.new(identity.secret, canonical, hashlib.sha256).hexdigest()


def verify(
    *,
    identity: ScraperIdentity | None,
    key_id: str,
    scraper_id: str,
    tenant_id: str,
    campaign_id: str,
    request_id: str,
    timestamp: str,
    nonce: str,
    supplied_signature: str,
    supplied_hash: str,
    version: str,
    body: bytes,
    nonces: NonceLedger,
    now: int | None = None,
    ttl: int = 300,
) -> None:
    if (
        identity is None
        or identity.scraper_id != scraper_id
        or identity.key_id != key_id
    ):
        raise ScraperAuthenticationError("UNKNOWN_SCRAPER_IDENTITY")
    if version != "hmac-sha256-v2" or not supplied_signature:
        raise ScraperAuthenticationError("MISSING_OR_INVALID_SIGNATURE")
    try:
        signed_at = int(timestamp)
    except ValueError as exc:
        raise ScraperAuthenticationError("EXPIRED_TIMESTAMP") from exc
    if abs((now or int(time.time())) - signed_at) > ttl:
        raise ScraperAuthenticationError("EXPIRED_TIMESTAMP")
    body_hash = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(body_hash, supplied_hash.removeprefix("sha256:")):
        raise ScraperAuthenticationError("MODIFIED_PAYLOAD")
    if identity.tenant_id != tenant_id or campaign_id not in identity.campaigns:
        raise ScraperAuthenticationError("WRONG_TENANT_BINDING")
    expected = signature(
        identity=identity,
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        request_id=request_id,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        version=version,
    )
    if not hmac.compare_digest(expected, supplied_signature):
        raise ScraperAuthenticationError("INVALID_SIGNATURE")
    nonces.consume(scraper_id, nonce)
