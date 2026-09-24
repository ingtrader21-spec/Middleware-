"""mTLS identity and scoped approval-token validation for private agents."""

from __future__ import annotations

import hashlib
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fastapi import HTTPException, Request

from app.core.config import settings
from app.core.controller import ApprovalTokens, ControllerError


CONTROLLER_SPIFFE = "spiffe://codestra.internal/controller/middleware"


def certificate_identity(scope: Mapping[str, Any]) -> tuple[str, str]:
    """Derive SPIFFE and fingerprint exclusively from TLS peer certificate DER.

    The ASGI TLS adapter must place the verified leaf DER bytes at
    ``scope['extensions']['tls']['client_cert']`` after chain validation.
    Client-supplied HTTP identity headers are intentionally ignored.
    """
    extensions = scope.get("extensions", {})
    der = extensions.get("tls", {}).get("client_cert")
    if not isinstance(der, bytes):
        raise HTTPException(401, "verified client certificate required")
    try:
        certificate = x509.load_der_x509_certificate(der)
        sans = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        if not isinstance(sans, x509.SubjectAlternativeName):
            raise ValueError("subject alternative name invalid")
        spiffe_ids = set(sans.get_values_for_type(x509.UniformResourceIdentifier))
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise HTTPException(401, "verified client certificate identity invalid") from exc
    if CONTROLLER_SPIFFE not in spiffe_ids:
        raise HTTPException(403, "controller identity denied")
    return CONTROLLER_SPIFFE, hashlib.sha256(der).hexdigest()


def approval_tokens() -> ApprovalTokens:
    path = Path(settings.controller_approval_signing_key_file)
    try:
        secret = path.read_bytes()
        return ApprovalTokens(secret)
    except (OSError, ControllerError) as exc:
        raise HTTPException(503, "approval verifier unavailable") from exc


def authorize_agent_request(
    request: Request,
    *,
    token: str,
    task_id: str,
    tenant_id: str,
    workspace: str,
    tool: str,
) -> dict[str, Any]:
    spiffe_id, fingerprint = certificate_identity(request.scope)
    try:
        claims = approval_tokens().verify(
            token,
            task_id=task_id,
            tenant_id=tenant_id,
            server_id="middleware",
            workspace=workspace,
            tool=tool,
            consume=True,
        )
    except ControllerError as exc:
        raise HTTPException(401, str(exc)) from exc
    return {**claims, "spiffe_id": spiffe_id, "certificate_fingerprint": fingerprint}
