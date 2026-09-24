"""Fail-closed production n8n transport with durable reservation."""

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.automation import canonical_hash
from app.core.config import settings
from app.core.service_tokens import client_credentials_token
from app.db.models import BroadEventDelivery, IntegrationEvent, N8nTargetAttestation


class N8nTransportError(RuntimeError):
    pass


async def attest_target(
    session: AsyncSession,
    identity_document: dict[str, Any],
    *,
    request_nonce: str,
) -> N8nTargetAttestation:
    """Persist short-lived exact target identity proof; health alone is insufficient."""
    expected = {
        "service": "n8n",
        "environment": "production",
        "canonical_host": "n8n.internal.codestra.agency",
        "image_digest": settings.n8n_production_image_digest,
        "workflow_package_sha256": settings.n8n_workflow_package_sha256,
    }
    if (
        not all(expected.values())
        or any(identity_document.get(key) != value for key, value in expected.items())
        or identity_document.get("health") != "healthy"
        or identity_document.get("readiness") != "ready"
        or not identity_document.get("n8n_version")
        or identity_document.get("nonce") != request_nonce
    ):
        raise N8nTransportError("n8n target identity attestation failed")
    unsigned = {
        key: value for key, value in identity_document.items() if key != "evidence_hash"
    }
    if identity_document.get("evidence_hash") != f"sha256:{canonical_hash(unsigned)}":
        raise N8nTransportError("n8n target evidence hash failed")
    now = datetime.now(UTC)
    try:
        issued_at = datetime.fromisoformat(str(identity_document["issued_at"]))
        expires_at = datetime.fromisoformat(str(identity_document["expires_at"]))
    except (KeyError, ValueError) as exc:
        raise N8nTransportError("n8n target evidence time is invalid") from exc
    if (
        issued_at > now
        or expires_at <= now
        or expires_at - issued_at > timedelta(minutes=5)
    ):
        raise N8nTransportError("n8n target evidence is stale")
    result = N8nTargetAttestation(
        target_identity=settings.n8n_production_target_identity,
        canonical_host=expected["canonical_host"],
        target_environment=expected["environment"],
        image_digest=expected["image_digest"],
        version=str(identity_document["n8n_version"]),
        workflow_package_sha256=expected["workflow_package_sha256"],
        request_nonce=request_nonce,
        verified_at=now,
        expires_at=expires_at,
        result="PASS",
        evidence_hash=canonical_hash(identity_document),
    )
    session.add(result)
    await session.commit()
    return result


async def reserve_delivery(
    session: AsyncSession,
    *,
    event: IntegrationEvent,
    workflow_id: str,
    workflow_version: str,
    policy_hash: str,
) -> tuple[BroadEventDelivery, bool]:
    """Commit an immutable one-attempt reservation before any network action."""
    reservation = BroadEventDelivery(
        event_id=event.id,
        workflow_id=workflow_id,
        workflow_version=workflow_version,
        idempotency_key=event.idempotency_key,
        target_identity=settings.n8n_production_target_identity,
        target_environment="production",
        payload_hash=event.payload_hash,
        policy_hash=policy_hash,
        attempt_number=1,
        status="RESERVED",
        reserved_at=datetime.now(UTC),
    )
    session.add(reservation)
    try:
        await session.commit()
        return reservation, False
    except IntegrityError:
        await session.rollback()
        existing = await session.scalar(
            select(BroadEventDelivery).where(
                BroadEventDelivery.event_id == event.id,
                BroadEventDelivery.workflow_id == workflow_id,
                BroadEventDelivery.workflow_version == workflow_version,
                BroadEventDelivery.idempotency_key == event.idempotency_key,
            )
        )
        if existing is None:
            raise
        return existing, True


async def submit_reserved(
    session: AsyncSession,
    delivery_id: UUID,
    envelope: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Submit exactly once to the configured internal target; never follow redirects."""
    if not settings.broad_event_pipeline_enabled:
        raise N8nTransportError("canonical broad-event gates are disabled")
    delivery = await session.get(BroadEventDelivery, delivery_id, with_for_update=True)
    if delivery is None or delivery.status != "RESERVED":
        raise N8nTransportError("delivery is not reserved")
    if canonical_hash(envelope["payload"]) != delivery.payload_hash:
        raise N8nTransportError("payload hash mismatch")
    if (
        not settings.n8n_production_target_url
        or delivery.target_identity != settings.n8n_production_target_identity
    ):
        raise N8nTransportError("production target is not attested")
    attestation = await session.scalar(
        select(N8nTargetAttestation)
        .where(
            N8nTargetAttestation.target_identity == delivery.target_identity,
            N8nTargetAttestation.target_environment == "production",
            N8nTargetAttestation.image_digest == settings.n8n_production_image_digest,
            N8nTargetAttestation.result == "PASS",
            N8nTargetAttestation.expires_at > datetime.now(UTC),
        )
        .order_by(N8nTargetAttestation.verified_at.desc())
        .limit(1)
    )
    if attestation is None:
        raise N8nTransportError("fresh production target attestation is required")
    delivery.status = "TARGET_ATTESTED"
    await session.commit()
    delivery = await session.get(BroadEventDelivery, delivery_id, with_for_update=True)
    if delivery is None or delivery.status != "TARGET_ATTESTED":
        raise N8nTransportError("target attestation transition failed")
    delivery.status = "SUBMITTING"
    await session.commit()
    encoded = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    owns_client = client is None
    transport_client = client or httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10.0),
        verify=settings.n8n_target_ca_file or True,
        trust_env=False,
    )
    token_client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(5.0),
        trust_env=False,
    )
    try:
        token = await client_credentials_token(
            token_url=settings.middleware_n8n_token_url,
            client_id=settings.middleware_n8n_client_id,
            client_secret_file=settings.middleware_n8n_client_secret_file,
            audience=settings.middleware_n8n_audience,
            scope=settings.middleware_n8n_scope,
            client=token_client,
        )
        timestamp = str(int(time.time()))
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": delivery.idempotency_key,
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Nonce": uuid4().hex,
            "X-Codestra-Body-SHA256": f"sha256:{canonical_hash_bytes(encoded)}",
            "X-Codestra-Correlation-ID": str(envelope["correlation_id"]),
        }
        response = await transport_client.post(
            settings.n8n_production_target_url, content=encoded, headers=headers
        )
    finally:
        await token_client.aclose()
        if owns_client:
            await transport_client.aclose()
    delivery = await session.get(BroadEventDelivery, delivery_id, with_for_update=True)
    if delivery is None:
        raise N8nTransportError("reserved delivery disappeared")
    delivery.submitted_at = datetime.now(UTC)
    if response.is_redirect:
        delivery.status = "FAILED"
        delivery.error_class = "REDIRECT_REJECTED"
        delivery.failed_at = datetime.now(UTC)
        await session.commit()
        raise N8nTransportError("redirect rejected")
    if response.status_code != 202:
        delivery.status = "FAILED"
        delivery.error_class = f"HTTP_{response.status_code}"
        delivery.failed_at = datetime.now(UTC)
        await session.commit()
        raise N8nTransportError("n8n did not durably accept delivery")
    try:
        accepted = response.json()
    except ValueError as exc:
        raise N8nTransportError("invalid accepted response") from exc
    required = {
        "delivery_id": str(delivery.delivery_id),
        "event_id": envelope["event_id"],
        "workflow_id": delivery.workflow_id,
        "workflow_version": delivery.workflow_version,
    }
    if any(
        accepted.get(key) != value for key, value in required.items()
    ) or not accepted.get("registration_id"):
        delivery.status = "FAILED"
        delivery.error_class = "ACCEPTED_RESPONSE_MISMATCH"
        delivery.failed_at = datetime.now(UTC)
        await session.commit()
        raise N8nTransportError("accepted response binding mismatch")
    delivery.status = "ACCEPTED"
    delivery.response_received_at = datetime.now(UTC)
    delivery.response_hash = canonical_hash(accepted)
    await session.commit()
    return accepted


def canonical_hash_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()
