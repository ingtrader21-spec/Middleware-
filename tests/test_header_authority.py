import pytest
from app.core.header_authority import (
    AUTHORIZATION, TENANT_ID, CORRELATION_ID, REQUEST_ID, IDEMPOTENCY_KEY,
    assert_canonical_v3_header,
)

def test_canonical_v3_header_names_are_stable():
    assert AUTHORIZATION == "Authorization"
    assert TENANT_ID == "X-Tenant-ID"
    assert CORRELATION_ID == "X-Correlation-ID"
    assert REQUEST_ID == "X-Request-ID"
    assert IDEMPOTENCY_KEY == "Idempotency-Key"

@pytest.mark.parametrize("legacy", [
    "X-Codestra-Tenant-Id", "X-Codestra-Tenant",
    "X-Codestra-Correlation-ID", "X-Codestra-Request-ID",
])
def test_signed_protocol_names_are_not_v3_aliases(legacy):
    with pytest.raises(ValueError, match="reserved"):
        assert_canonical_v3_header(legacy)

@pytest.mark.parametrize("canonical", [
    "Authorization", "X-Tenant-ID", "X-Correlation-ID",
    "X-Request-ID", "Idempotency-Key", "traceparent", "tracestate",
])
def test_canonical_names_are_accepted(canonical):
    assert assert_canonical_v3_header(canonical) == canonical


def test_ordinary_api_sources_do_not_declare_reserved_codestra_identity_headers():
    root = __import__("pathlib").Path("app")
    signed_protocol_files = {
        root / "api/v1/n8n_runtime.py",
        root / "service.py",
        root / "nats_transport.py",
        root / "core/service_client.py",
    }
    forbidden = (
        'Header(alias="X-Codestra-Tenant',
        'Header(alias="X-Codestra-Correlation-ID")',
        'Header(alias="X-Codestra-Request-ID")',
    )
    offenders = []
    for source in root.rglob("*.py"):
        if source in signed_protocol_files:
            continue
        text = source.read_text(encoding="utf-8")
        if any(marker in text for marker in forbidden):
            offenders.append(str(source))
    assert offenders == []
