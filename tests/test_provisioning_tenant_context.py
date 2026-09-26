from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.core.provisioning_auth import ProvisioningPrincipal, resolve_tenant_context


def principal(*tenants: str) -> ProvisioningPrincipal:
    return ProvisioningPrincipal(
        subject="svc:test",
        authorized_party="provisioning-service",
        tenant_ids=frozenset(tenants),
    )


def test_single_tenant_principal_resolves_without_selector() -> None:
    assert resolve_tenant_context(principal("tenant-a")) == "tenant-a"


def test_explicit_selector_must_be_authorized() -> None:
    p = principal("tenant-a", "tenant-b")
    assert resolve_tenant_context(p, "tenant-b") == "tenant-b"
    with pytest.raises(HTTPException) as exc:
        resolve_tenant_context(p, "tenant-c")
    assert exc.value.status_code == 403


def test_multi_tenant_principal_requires_explicit_selector() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_tenant_context(principal("tenant-a", "tenant-b"))
    assert exc.value.status_code == 403


def test_empty_tenant_claim_fails_closed() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_tenant_context(principal())
    assert exc.value.status_code == 403
