from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

SERVICE_IDENTITY = "codestra-middleware"
SERVICE_AUDIENCE = "codestra-odoo-recording-api"
UPSERT_PATH = "/codestra/api/v1/recordings/upsert"


class OdooAcknowledgement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: str = Field(pattern=r"^1\.0$")
    recording_uid: str = Field(pattern=r"^REC-[0-9a-f]{32}$")
    odoo_record_id: int = Field(gt=0)
    call_link_status: str = Field(min_length=1, max_length=32)
    lead_link_status: str = Field(min_length=1, max_length=32)
    campaign_link_status: str = Field(min_length=1, max_length=32)
    agent_link_status: str = Field(min_length=1, max_length=32)
    storage_status: str = Field(min_length=1, max_length=32)
    retention_class: str = Field(min_length=1, max_length=32)
    retention_until: datetime | None
    legal_hold: bool
    updated_at: datetime


class OdooRecordingPort(Protocol):
    async def upsert(
        self, metadata: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]: ...


class OdooRecordingClient:
    """Service-authenticated metadata-only client for authoritative Odoo writes."""

    def __init__(
        self,
        base_url: str,
        hmac_secret: str,
        environment: str,
        client: httpx.AsyncClient | None = None,
        *,
        clock: Any = time.time,
        nonce_factory: Any = lambda: secrets.token_hex(16),
    ) -> None:
        if not base_url.startswith("https://") or not hmac_secret:
            raise ValueError("Odoo HTTPS HMAC service authentication is required")
        self.base_url = base_url.rstrip("/")
        self._hmac_secret = hmac_secret.encode()
        self.environment = environment
        self.client = client or httpx.AsyncClient(timeout=15)
        self._clock = clock
        self._nonce_factory = nonce_factory

    def _signed_headers(
        self,
        method: str,
        path: str,
        body: bytes,
        idempotency_key: str,
    ) -> dict[str, str]:
        timestamp = str(int(self._clock()))
        nonce = self._nonce_factory()
        content_sha256 = hashlib.sha256(body).hexdigest()
        canonical = (
            f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n"
            f"{idempotency_key}\n{content_sha256}"
        ).encode()
        signature = hmac.new(self._hmac_secret, canonical, hashlib.sha256).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-Service-Identity": SERVICE_IDENTITY,
            "X-Service-Audience": SERVICE_AUDIENCE,
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Nonce": nonce,
            "X-Codestra-Content-SHA256": content_sha256,
            "X-Codestra-Signature": signature,
            "Idempotency-Key": idempotency_key,
            "X-Codestra-Environment": self.environment,
        }

    async def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        idempotency_key: str,
    ) -> httpx.Response:
        body = (
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            if payload is not None
            else b""
        )
        return await self.client.request(
            method,
            f"{self.base_url}{path}",
            content=body,
            headers=self._signed_headers(method, path, body, idempotency_key),
        )

    async def upsert(
        self, metadata: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        forbidden = {"file", "audio", "mp3", "upload_url", "object_key"}
        if forbidden.intersection(metadata):
            raise ValueError("Odoo recording request must contain metadata only")
        response = await self._request("POST", UPSERT_PATH, metadata, idempotency_key)
        response.raise_for_status()
        return OdooAcknowledgement.model_validate(response.json()).model_dump(
            mode="json"
        )

    async def get(self, recording_uid: str, idempotency_key: str) -> dict[str, Any]:
        path = f"/codestra/api/v1/recordings/{recording_uid}"
        response = await self._request("GET", path, None, idempotency_key)
        response.raise_for_status()
        return response.json()

    async def update_status(
        self,
        recording_uid: str,
        status: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        path = f"/codestra/api/v1/recordings/{recording_uid}/status"
        response = await self._request("POST", path, status, idempotency_key)
        response.raise_for_status()
        return response.json()


class AcknowledgingOdooClient:
    async def upsert(
        self, metadata: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        return {
            "contract_version": metadata["contract_version"],
            "recording_uid": metadata["recording_uid"],
            "odoo_record_id": 1,
            "call_link_status": "linked",
            "lead_link_status": "not_present",
            "campaign_link_status": "linked",
            "agent_link_status": "linked",
            "storage_status": metadata["storage_status"],
            "retention_class": metadata["retention_class"],
            "retention_until": metadata["retention_until"],
            "legal_hold": metadata["legal_hold"],
            "updated_at": datetime.now().astimezone().isoformat(),
        }
