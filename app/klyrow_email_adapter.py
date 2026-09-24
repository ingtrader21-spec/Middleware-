from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import httpx
from pydantic import TypeAdapter, ValidationError
from pydantic.networks import EmailStr

from app.core.config import ConfigurationError
from .temporal_workflows import ActivityResult, CommandExecutionRequest

EMAIL_ADDRESS = TypeAdapter(EmailStr)


class KlyrowEmailAdapterError(RuntimeError):
    pass


class KlyrowEmailAdapter:
    """Transactional email transport from the durable command plane to Klyrow.

    This is the general ``email.`` channel. It is a sibling of
    :class:`~app.klyrow_alert_adapter.KlyrowAlertAdapter`, which is the bounded
    fixed-recipient observability case of the same provider API. Both speak the
    same authenticated contract; only this one accepts caller-supplied
    recipients, and so validates them rather than pinning them to a policy.

    Klyrow remains the email provider authority: suppression lists, bounce and
    complaint handling, domain reputation and DKIM signing stay on its side.
    This class owns only authenticated command translation and read-back.

    A write that does not return a readable answer is an unknown outcome, never
    a failure. It is resolved by reading the message back under the command
    identity before control returns.
    """

    COMMAND_TYPE = "email.message.send.v1"
    TARGET = "klyrow-email"
    CAPABILITY = "EMAIL_DELIVERY"
    MESSAGE_PATH = "/v1/email/messages"
    MESSAGE_STATUS_PATH = "/v1/email/messages/{message_id}"
    TOKEN_URL = (
        "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
    )
    CLIENT_ID = "middleware-email-delivery"
    AUDIENCE = "klyrow-email"
    SCOPES = "email.message.send email.message.read"
    # The Klyrow email API is reachable only on the private service network.
    ALLOWED_BASE_URLS = frozenset(
        {
            "https://10.40.0.4:18000",
            "https://klyrow-email-api:18000",
        }
    )
    # Klyrow persists one durable lifecycle and provider identity per command.
    MAX_RECIPIENTS = 1
    ACCEPTED_STATUSES = frozenset(
        {"accepted", "queued", "sending", "sent", "delivered"}
    )
    # Mirrors the connector manifest's forbidden_payload_keys.
    FORBIDDEN_PAYLOAD_KEYS = frozenset(
        {
            "access_token",
            "client_secret",
            "password",
            "private_key",
            "provider_token",
            "refresh_token",
        }
    )

    def __init__(
        self,
        settings: Any,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.settings = settings
        self.env = os.environ if env is None else env
        self._token: tuple[str, float] | None = None
        self._token_lock = asyncio.Lock()

    def _required(self, name: str) -> str:
        value = self.env.get(name, "").strip()
        if not value:
            raise ConfigurationError(
                f"{name} is required for the Klyrow email adapter"
            )
        return value

    def _secret_file(self, name: str) -> str:
        raw_path = self._required(name)
        path = Path(raw_path)
        if not path.is_absolute():
            raise ConfigurationError(f"{name} must be an absolute mounted path")
        try:
            info = path.lstat()
        except OSError as exc:
            raise ConfigurationError(f"{name} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ConfigurationError(f"{name} must be a regular non-symlink file")
        if info.st_mode & 0o077:
            raise ConfigurationError(f"{name} must not be group/world accessible")
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError(f"{name} cannot be read") from exc
        if len(value) < 32:
            raise ConfigurationError(f"{name} must contain at least 32 characters")
        return value

    def _base_url(self) -> str:
        value = self._required("KLYROW_EMAIL_API_BASE_URL").rstrip("/")
        if value not in self.ALLOWED_BASE_URLS:
            raise ConfigurationError(
                "KLYROW_EMAIL_API_BASE_URL is not an approved private endpoint"
            )
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigurationError(
                "KLYROW email endpoint must be a credential-free HTTPS origin"
            )
        return value

    def _tls_context(self) -> ssl.SSLContext:
        ca_file = self._required("KLYROW_EMAIL_MTLS_CA_FILE")
        cert_file = self._required("KLYROW_EMAIL_MTLS_CERT_FILE")
        key_file = self._required("KLYROW_EMAIL_MTLS_KEY_FILE")
        for name, value in (
            ("KLYROW_EMAIL_MTLS_CA_FILE", ca_file),
            ("KLYROW_EMAIL_MTLS_CERT_FILE", cert_file),
            ("KLYROW_EMAIL_MTLS_KEY_FILE", key_file),
        ):
            path = Path(value)
            if not path.is_absolute() or path.is_symlink() or not path.is_file():
                raise ConfigurationError(f"{name} must be an absolute regular file")
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        return context

    def _validate_identity(self, request: CommandExecutionRequest) -> None:
        if request.target != self.TARGET:
            raise KlyrowEmailAdapterError(
                "Klyrow email adapter does not own this command target"
            )
        if request.capability != self.CAPABILITY:
            raise KlyrowEmailAdapterError(
                "Klyrow email command capability must be EMAIL_DELIVERY"
            )
        if request.command_type != self.COMMAND_TYPE:
            raise KlyrowEmailAdapterError(
                f"unsupported Klyrow email command type: {request.command_type}"
            )
        if request.command_version != "1.0":
            raise KlyrowEmailAdapterError(
                "Klyrow email command version must be 1.0"
            )

    def _validate_payload(
        self,
        request: CommandExecutionRequest,
    ) -> dict[str, Any]:
        self._validate_identity(request)
        payload = request.payload
        leaked = sorted(self.FORBIDDEN_PAYLOAD_KEYS.intersection(payload))
        if leaked:
            raise KlyrowEmailAdapterError(
                "command payload carries forbidden secret keys: " + ", ".join(leaked)
            )
        if payload.get("channel") != "email":
            raise KlyrowEmailAdapterError("Klyrow email command channel must be email")

        sender = payload.get("from")
        if not isinstance(sender, str) or not self._is_email(sender):
            raise KlyrowEmailAdapterError(
                "Klyrow email command sender is not a valid address"
            )

        recipients = payload.get("to")
        if (
            not isinstance(recipients, list)
            or not recipients
            or len(recipients) > self.MAX_RECIPIENTS
        ):
            raise KlyrowEmailAdapterError(
                "Klyrow email command must carry exactly one recipient"
            )
        if not all(
            isinstance(value, str) and self._is_email(value) for value in recipients
        ):
            raise KlyrowEmailAdapterError(
                "Klyrow email command recipients are not all valid addresses"
            )
        if len(set(recipients)) != len(recipients):
            raise KlyrowEmailAdapterError(
                "Klyrow email command recipients must be unique"
            )

        content = payload.get("content")
        if not isinstance(content, dict):
            raise KlyrowEmailAdapterError("Klyrow email command content is missing")
        if not any(content.get(key) for key in ("text", "html", "templateId")):
            raise KlyrowEmailAdapterError(
                "Klyrow email content requires text, html, or templateId"
            )
        return payload

    @staticmethod
    def _is_email(value: str) -> bool:
        try:
            EMAIL_ADDRESS.validate_python(value)
        except ValidationError:
            return False
        return True

    def _require_active(
        self,
        request: CommandExecutionRequest,
    ) -> dict[str, Any]:
        payload = self._validate_payload(request)
        if not self.settings.email_delivery_enabled:
            raise KlyrowEmailAdapterError(
                "email delivery is disabled by EMAIL_DELIVERY_ENABLED or its "
                "umbrella switch EXTERNAL_DELIVERY_ENABLED"
            )
        if self.settings.app_env == "production":
            self._validate_production_authorization(request, payload)
        return payload

    def _validate_production_authorization(
        self,
        request: CommandExecutionRequest,
        payload: dict[str, Any],
    ) -> None:
        metadata = payload.get("metadata")
        authority = (
            metadata.get("productionAuthorization")
            if isinstance(metadata, dict)
            else None
        )
        if not isinstance(authority, dict):
            raise KlyrowEmailAdapterError(
                "Middleware production authorization is required"
            )
        category = str(
            payload.get("metadata", {}).get("category") or "transactional"
        ).lower()
        required = {
            "schemaVersion": "1.0",
            "tenantId": request.tenant_id,
            "authorizationState": "ACTIVE",
            "killSwitchOpen": True,
            "provider": "klyrow-postal",
            "environment": "production",
            "category": category,
        }
        if any(authority.get(key) != value for key, value in required.items()):
            raise KlyrowEmailAdapterError(
                "Middleware production authorization is invalid"
            )
        if authority.get("mode") not in {
            "TRANSACTIONAL_CANARY",
            "TRANSACTIONAL_PRODUCTION",
        }:
            raise KlyrowEmailAdapterError(
                "Middleware production mode is not transactional"
            )
        if (
            not isinstance(authority.get("policyVersion"), int)
            or authority["policyVersion"] < 1
            or not isinstance(authority.get("changeId"), str)
            or len(authority["changeId"]) < 3
        ):
            raise KlyrowEmailAdapterError(
                "Middleware production authorization identity is invalid"
            )
        source_sha = str(getattr(self.settings, "source_sha", "") or "")
        if len(source_sha) != 40 or authority.get("approvedReleaseSha") != source_sha:
            raise KlyrowEmailAdapterError(
                "Middleware production authorization release does not match runtime"
            )
        try:
            valid_from = datetime.fromisoformat(str(authority["validFrom"]))
            valid_until = datetime.fromisoformat(str(authority["validUntil"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise KlyrowEmailAdapterError(
                "Middleware production authorization window is invalid"
            ) from exc
        now = datetime.now(UTC)
        if (
            valid_from.tzinfo is None
            or valid_until.tzinfo is None
            or now < valid_from.astimezone(UTC)
            or now >= valid_until.astimezone(UTC)
        ):
            raise KlyrowEmailAdapterError(
                "Middleware production authorization is outside its window"
            )

    async def _access_token(self) -> str:
        now = time.monotonic()
        if self._token is not None and self._token[1] > now + 30:
            return self._token[0]
        async with self._token_lock:
            now = time.monotonic()
            if self._token is not None and self._token[1] > now + 30:
                return self._token[0]
            token_url = self.env.get(
                "KLYROW_EMAIL_OIDC_TOKEN_URL",
                self.TOKEN_URL,
            ).strip()
            if token_url != self.TOKEN_URL:
                raise ConfigurationError(
                    "KLYROW email token URL must use the canonical issuer"
                )
            client_id = self.env.get(
                "KLYROW_EMAIL_OIDC_CLIENT_ID",
                self.CLIENT_ID,
            ).strip()
            if client_id != self.CLIENT_ID:
                raise ConfigurationError("KLYROW email client ID is not approved")
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": self._secret_file(
                            "KLYROW_EMAIL_OIDC_CLIENT_SECRET_FILE"
                        ),
                        "audience": self.AUDIENCE,
                        "scope": self.SCOPES,
                    },
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                value = response.json()
            token = value.get("access_token") if isinstance(value, dict) else None
            expires_in = value.get("expires_in") if isinstance(value, dict) else None
            if not isinstance(token, str) or not token:
                raise KlyrowEmailAdapterError("Klyrow email access token is missing")
            if (
                isinstance(expires_in, bool)
                or not isinstance(expires_in, int)
                or not 30 <= expires_in <= 900
            ):
                raise KlyrowEmailAdapterError("Klyrow email token lifetime is invalid")
            self._token = (token, time.monotonic() + min(expires_in, 300))
            return token

    async def _headers(self, request: CommandExecutionRequest) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": "Bearer " + await self._access_token(),
            "Content-Type": "application/json",
            "X-Tenant-ID": request.tenant_id,
            "X-Correlation-ID": request.correlation_id,
            "Idempotency-Key": request.idempotency_key,
            "X-Codestra-Classification": "transactional",
        }

    @staticmethod
    def _provider_document(
        request: CommandExecutionRequest,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        content = payload["content"]
        metadata = dict(payload.get("metadata") or {})
        authority = metadata.get("productionAuthorization")
        if isinstance(authority, dict):
            authority = dict(authority)
            authority["commandBinding"] = {
                "messageId": request.command_id,
                "correlationId": request.correlation_id,
                "idempotencyKeySha256": hashlib.sha256(
                    request.idempotency_key.encode("utf-8")
                ).hexdigest(),
                "sender": str(payload["from"]).lower(),
                "recipientsSha256": hashlib.sha256(
                    json.dumps(
                        [str(value).lower() for value in payload["to"]],
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
            }
            metadata["productionAuthorization"] = authority
        document: dict[str, Any] = {
            "message_id": request.command_id,
            "tenant_id": request.tenant_id,
            "sender": payload["from"],
            "recipients": payload["to"],
            "subject": content.get("subject"),
            "text": content.get("text"),
            "html": content.get("html"),
            "stream": "transactional",
            "metadata": metadata,
        }
        # Template rendering stays on the Klyrow side; Middleware forwards the
        # reference rather than expanding it.
        if content.get("templateId"):
            document["template_id"] = content["templateId"]
            if content.get("templateVersion") is not None:
                document["template_version"] = content["templateVersion"]
            if content.get("variables") is not None:
                document["variables"] = content["variables"]
        if payload.get("scheduled_at"):
            document["scheduled_at"] = payload["scheduled_at"]
        return document

    @staticmethod
    def _provider_id(value: Any) -> str:
        if not isinstance(value, dict):
            return ""
        candidate = (
            value.get("message_id") or value.get("operation_id") or value.get("id")
        )
        return str(candidate or "")

    async def execute(self, request: CommandExecutionRequest) -> ActivityResult:
        payload = self._require_active(request)
        body = self._provider_document(request, payload)
        # Resolve endpoint, TLS material and credentials *before* the attempt.
        # A misconfiguration is a clean non-retryable failure; folding it into
        # the send would misreport it as an unknown outcome that might have
        # delivered mail.
        url = self._base_url() + self.MESSAGE_PATH
        tls_context = self._tls_context()
        headers = await self._headers(request)
        try:
            async with httpx.AsyncClient(
                verify=tls_context,
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    url,
                    json=body,
                    headers=headers,
                )
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            try:
                reconciled = await self.readback(request)
            except KlyrowEmailAdapterError as readback_error:
                raise KlyrowEmailAdapterError(
                    "Klyrow email outcome remains unknown after read-back failed"
                ) from readback_error
            if reconciled.status == "matched":
                return ActivityResult(
                    status="accepted",
                    detail=(
                        "Klyrow write response was interrupted; "
                        "read-back confirmed acceptance"
                    ),
                    provider_operation_id=request.command_id,
                    readback_evidence=reconciled.readback_evidence,
                )
            raise KlyrowEmailAdapterError(
                "Klyrow email submission failed"
            ) from exc
        if self._provider_id(value) != request.command_id:
            raise KlyrowEmailAdapterError(
                "Klyrow response did not bind the command identity"
            )
        return ActivityResult(
            status="accepted",
            detail="Klyrow accepted the transactional email command",
            provider_operation_id=request.command_id,
        )

    async def readback(self, request: CommandExecutionRequest) -> ActivityResult:
        """Read the recorded message back without replaying the send."""
        payload = self._validate_payload(request)
        path = self.MESSAGE_STATUS_PATH.format(
            message_id=quote(request.command_id, safe="")
        )
        url = self._base_url() + path
        tls_context = self._tls_context()
        headers = await self._headers(request)
        try:
            async with httpx.AsyncClient(
                verify=tls_context,
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KlyrowEmailAdapterError("Klyrow email read-back failed") from exc
        if not isinstance(value, dict):
            raise KlyrowEmailAdapterError("Klyrow email read-back is malformed")

        recipients = value.get("recipients") or value.get("to")
        sender = value.get("sender") or value.get("from")
        status_value = str(value.get("status") or "").lower()
        if isinstance(recipients, str):
            recipient_matches = [recipients] == payload["to"]
        elif isinstance(recipients, list):
            recipient_matches = recipients == payload["to"]
        else:
            recipient_matches = False
        if (
            self._provider_id(value) == request.command_id
            and recipient_matches
            and sender == payload["from"]
            and status_value in self.ACCEPTED_STATUSES
        ):
            return ActivityResult(
                status="matched",
                detail="Klyrow read-back matched the transactional email intent",
                provider_operation_id=request.command_id,
                readback_evidence={
                    "schema_version": "1.0",
                    "message_id": request.command_id,
                    "status": status_value,
                    "recipient_count": len(payload["to"]),
                },
            )
        return ActivityResult(
            status="mismatch",
            detail="Klyrow read-back did not match the transactional email intent",
            provider_operation_id=request.command_id,
        )
