"""Authenticated, durable BREERO CRM event ingress."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_session

PATH = "/api/v1/integrations/breero/events"
VERSION = "HMAC-V2"
ALLOWED_EVENTS = {
    "breero.service_request.created": "BREERO_CUSTOMER_REQUESTS",
    "breero.contact_request.created": "BREERO_SUPPORT_BUSINESS",
    "breero.provider_interest.created": "BREERO_PROVIDER_RECRUITMENT",
    "breero.lead_dispute.created": "BREERO_LEAD_DISPUTES",
}
AUTH_HEADERS = (
    "X-Codestra-Signature-Version", "X-Service-Identity", "X-Service-Audience",
    "X-Codestra-Timestamp", "X-Codestra-Nonce", "X-Codestra-Content-SHA256",
    "X-Codestra-Signature", "X-HMAC-Key-ID", "X-Codestra-Environment",
    "X-Codestra-Scope", "X-Codestra-Tenant", "Idempotency-Key",
)

router = APIRouter(tags=["breero-integration"])


class BreeroEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID
    event_type: str
    schema_version: int
    aggregate_id: UUID
    aggregate_version: int = Field(ge=1)
    occurred_at: datetime
    idempotency_key: str = Field(min_length=1, max_length=255)
    source: str
    payload: dict = Field(default_factory=dict)


def _identities() -> dict:
    if not settings.breero_hmac_identities_file:
        raise HTTPException(503, "BREERO identity registry unavailable")
    try:
        value = json.loads(Path(settings.breero_hmac_identities_file).read_text())
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "BREERO identity registry unavailable") from exc
    return value if isinstance(value, dict) else {}


def _headers(request: Request) -> dict[str, str]:
    raw = [name.lower() for name, _ in request.scope.get("headers", [])]
    if any(raw.count(name.lower().encode()) != 1 for name in AUTH_HEADERS):
        raise HTTPException(401, "missing or duplicate authentication header")
    return {name: request.headers[name] for name in AUTH_HEADERS}


def _authenticate(request: Request, body: bytes, event: BreeroEvent) -> tuple[dict, str]:
    headers = _headers(request)
    key_id = headers["X-HMAC-Key-ID"]
    identity = _identities().get(key_id)
    if not isinstance(identity, dict) or not identity.get("enabled", False):
        raise HTTPException(401, "unauthorized BREERO identity")
    expected = {
        "identity": headers["X-Service-Identity"], "audience": headers["X-Service-Audience"],
        "environment": headers["X-Codestra-Environment"], "scope": headers["X-Codestra-Scope"],
        "tenant": headers["X-Codestra-Tenant"],
        "source_ip": request.headers.get("X-Codestra-Verified-Source-IP", ""),
    }
    if any(not hmac.compare_digest(str(identity.get(k, "")), v) for k, v in expected.items()):
        raise HTTPException(403, "BREERO identity binding rejected")
    if headers["X-Codestra-Signature-Version"] != VERSION:
        raise HTTPException(401, "unsupported signature version")
    if headers["Idempotency-Key"] != event.idempotency_key:
        raise HTTPException(409, "idempotency binding mismatch")
    digest = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(digest, headers["X-Codestra-Content-SHA256"]):
        raise HTTPException(401, "body digest mismatch")
    try:
        instant = datetime.fromisoformat(headers["X-Codestra-Timestamp"].replace("Z", "+00:00"))
        age = abs((datetime.now(UTC) - instant.astimezone(UTC)).total_seconds())
    except ValueError as exc:
        raise HTTPException(401, "invalid timestamp") from exc
    if age > settings.breero_signature_ttl_seconds:
        raise HTTPException(401, "expired timestamp")
    canonical = "\n".join((VERSION, "POST", PATH, headers["X-Codestra-Timestamp"],
        headers["X-Codestra-Nonce"], expected["identity"], expected["audience"],
        expected["environment"], expected["scope"], event.idempotency_key, digest))
    try:
        secret = Path(str(identity["secret_file"])).read_bytes().strip()
    except (KeyError, OSError) as exc:
        raise HTTPException(503, "BREERO signing key unavailable") from exc
    signature = hmac.new(secret, canonical.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, headers["X-Codestra-Signature"]):
        raise HTTPException(401, "invalid signature")
    return identity, headers["X-Codestra-Nonce"]


@router.post(PATH, status_code=202)
async def receive_breero_event(request: Request, db: AsyncSession = Depends(get_session)) -> dict:
    if not settings.breero_ingress_enabled:
        raise HTTPException(503, "BREERO ingress disabled")
    body = await request.body()
    if len(body) > settings.breero_request_max_bytes:
        raise HTTPException(413, "request too large")
    try:
        event = BreeroEvent.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(422, "invalid BREERO event") from exc
    if event.schema_version != 1 or event.source != "breero" or event.event_type not in ALLOWED_EVENTS:
        raise HTTPException(422, "unsupported BREERO event contract")
    if len(event.payload) > 20:
        raise HTTPException(422, "BREERO payload exceeds property limit")
    identity, nonce = _authenticate(request, body, event)
    payload_hash = hashlib.sha256(body).hexdigest()
    idem_hash = hashlib.sha256(event.idempotency_key.encode()).hexdigest()
    existing = (await db.execute(text("SELECT public_id,payload_hash,status FROM breero_event_receipt WHERE identity=:i AND idempotency_key_hash=:k"), {"i": identity["identity"], "k": idem_hash})).mappings().first()
    if existing:
        if existing["payload_hash"] != payload_hash:
            raise HTTPException(409, "idempotency key reused with different payload")
        return {"event_id": str(event.event_id), "status": "replayed", "middleware_receipt_id": existing["public_id"]}
    nonce_insert = await db.execute(text("INSERT INTO breero_replay_nonce(identity,nonce_hash,expires_at) VALUES (:i,:n,now() + make_interval(secs=>:ttl)) ON CONFLICT DO NOTHING RETURNING identity"), {"i": identity["identity"], "n": hashlib.sha256(nonce.encode()).hexdigest(), "ttl": settings.breero_signature_ttl_seconds})
    if nonce_insert.first() is None:
        raise HTTPException(409, "replayed nonce")
    receipt_id, outbox_id = f"BRR-{uuid4()}", uuid4()
    await db.execute(text("""INSERT INTO breero_event_receipt
      (public_id,event_id,event_type,schema_version,aggregate_id,aggregate_version,occurred_at,
       idempotency_key,source,identity,tenant,environment,scope,payload_hash,idempotency_key_hash,
       payload,status,route_key)
      VALUES (:p,:e,:t,:sv,:a,:v,:occurred,:idem,:source,:i,:tenant,:env,:scope,:ph,:ih,
              CAST(:payload AS jsonb),'queued',:route)"""),
      {"p": receipt_id,"e":str(event.event_id),"t":event.event_type,"sv":event.schema_version,
       "a":str(event.aggregate_id),"v":event.aggregate_version,"occurred":event.occurred_at,
       "idem":event.idempotency_key,"source":event.source,"i":identity["identity"],
       "tenant":identity["tenant"],"env":identity["environment"],"scope":identity["scope"],
       "ph":payload_hash,"ih":idem_hash,"payload":json.dumps(event.payload),
       "route":ALLOWED_EVENTS[event.event_type]})
    await db.execute(text("INSERT INTO breero_odoo_outbox(id,receipt_public_id,status,next_attempt_at) VALUES (:id,:r,'pending',now())"), {"id": outbox_id,"r":receipt_id})
    await db.execute(text("INSERT INTO breero_integration_audit(receipt_public_id,action,outcome,safe_detail) VALUES (:r,'event.accepted','accepted',:d)"), {"r":receipt_id,"d":ALLOWED_EVENTS[event.event_type]})
    await db.commit()
    return {"event_id": str(event.event_id), "status": "queued", "middleware_receipt_id": receipt_id}
