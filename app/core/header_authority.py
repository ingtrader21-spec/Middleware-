"""Canonical HTTP header authority for Middleware V3.

Public/control V3 APIs use the short transport names below.  X-Codestra-*
headers are reserved for explicitly versioned signed/internal protocols and
must not be introduced as aliases for canonical V3 request identity.
"""
from __future__ import annotations

AUTHORIZATION = "Authorization"
TENANT_ID = "X-Tenant-ID"
CORRELATION_ID = "X-Correlation-ID"
REQUEST_ID = "X-Request-ID"
IDEMPOTENCY_KEY = "Idempotency-Key"
TRACEPARENT = "traceparent"
TRACESTATE = "tracestate"

CANONICAL_V3_HEADERS = frozenset({
    AUTHORIZATION, TENANT_ID, CORRELATION_ID, REQUEST_ID, IDEMPOTENCY_KEY,
    TRACEPARENT, TRACESTATE,
})

# These names are protocol fields covered by signatures or legacy event
# contracts. They are not aliases for canonical V3 API headers.
SIGNED_PROTOCOL_HEADERS = frozenset({
    "X-Codestra-Tenant-Id",
    "X-Codestra-Tenant",
    "X-Codestra-Correlation-ID",
    "X-Codestra-Request-ID",
    "X-Codestra-Causation-ID",
    "X-Codestra-Timestamp",
    "X-Codestra-Nonce",
    "X-Codestra-Body-SHA256",
    "X-Codestra-Content-SHA256",
    "X-Codestra-Signature",
})


def assert_canonical_v3_header(name: str) -> str:
    """Reject signed-protocol names when declaring ordinary V3 API headers."""
    if name in SIGNED_PROTOCOL_HEADERS:
        raise ValueError(f"{name} is reserved for a signed/internal protocol")
    if name not in CANONICAL_V3_HEADERS:
        raise ValueError(f"{name} is not a canonical Middleware V3 header")
    return name
