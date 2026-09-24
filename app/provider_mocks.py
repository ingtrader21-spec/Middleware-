"""Deterministic, side-effect-free provider adapters for offline validation."""

from __future__ import annotations

from hashlib import sha256
from typing import Any


class MockProviderAdapter:
    """Return stable fixtures and never performs network or database I/O."""

    def __init__(self, provider: str) -> None:
        if provider not in {"qwen", "vicidial", "postiz"}:
            raise ValueError("unsupported mock provider")
        self.provider = provider
        self.calls: dict[str, int] = {}

    def execute(self, operation: str, key: str, outcome: str = "success", **payload: Any) -> dict[str, Any]:
        self.calls[key] = self.calls.get(key, 0) + 1
        digest = sha256(f"{self.provider}:{operation}:{key}".encode()).hexdigest()[:16]
        if outcome == "temporary_failure":
            return {"status": "RETRYABLE_FAILURE", "failure_class": "TEMPORARY_PROVIDER_ERROR", "fixture_id": digest}
        if outcome == "permanent_failure":
            return {"status": "FAILED", "failure_class": "BUSINESS_REJECTION", "fixture_id": digest}
        if outcome == "timeout":
            return {"status": "TIMEOUT", "failure_class": "NETWORK_TIMEOUT", "fixture_id": digest}
        if outcome in {"duplicate_callback", "duplicate"}:
            return {"status": "DUPLICATE", "duplicate": True, "fixture_id": digest}
        if outcome == "missing_result":
            return {"status": "MISSING_RESULT", "fixture_id": digest}
        if outcome == "reconciliation_mismatch":
            return {"status": "RECONCILIATION_MISMATCH", "fixture_id": digest}
        result = {"status": "COMPLETED", "fixture_id": digest, "provider": self.provider, "operation": operation}
        result.update(payload)
        return result


QWEN_MOCK = MockProviderAdapter("qwen")
VICIDIAL_MOCK = MockProviderAdapter("vicidial")
POSTIZ_MOCK = MockProviderAdapter("postiz")
