from __future__ import annotations

import asyncio
import json
import os
import ssl
import stat
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import httpx

from app.core.config import ConfigurationError, Settings
from .temporal_workflows import ActivityResult, CommandExecutionRequest


class KlyrowAlertAdapterError(RuntimeError):
    pass


class KlyrowAlertAdapter:
    """Bounded Middleware-owned adapter for one fixed observability recipient.

    The adapter never accepts a recipient or sender from an untrusted caller. Both
    values must match the reviewed repository policy embedded in the durable
    command. The Klyrow API remains the email provider authority; this class owns
    only authenticated command translation and read-back.
    """

    COMMAND_TYPE = "observability.alert.email.send.v1"
    TARGET = "klyrow-alert-email"
    CAPABILITY = "OBSERVABILITY_ALERT_EMAIL_DELIVERY"
    MESSAGE_PATH = "/v1/email/messages"
    MESSAGE_STATUS_PATH = "/v1/email/messages/{message_id}"
    TOKEN_URL = (
        "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
    )
    CLIENT_ID = "middleware-alert-delivery"
    AUDIENCE = "klyrow-email"
    SCOPES = "email.message.send email.message.read"
    ACTIVE_RECIPIENT = "appolon1908@gmail.com"
    LEGACY_READBACK_RECIPIENTS = frozenset({"appolon@codestra.co"})
    ALLOWED_BASE_URLS = frozenset(
        {
            "https://10.40.0.4:18000",
            "https://klyrow-email-api:18000",
        }
    )

    def __init__(
        self,
        settings: Settings,
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
                f"{name} is required for the Klyrow alert adapter"
            )
        return value

    def _explicit_bool(self, name: str) -> bool:
        value = self.env.get(name, "false").strip().lower()
        if value in {"true", "1", "yes", "on"}:
            return True
        if value in {"false", "0", "no", "off", ""}:
            return False
        raise ConfigurationError(f"{name} must be an explicit boolean")

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
        value = self._required("KLYROW_ALERT_API_BASE_URL").rstrip("/")
        if value not in self.ALLOWED_BASE_URLS:
            raise ConfigurationError(
                "KLYROW_ALERT_API_BASE_URL is not an approved private endpoint"
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
                "KLYROW alert endpoint must be a credential-free HTTPS origin"
            )
        return value

    def _tls_context(self) -> ssl.SSLContext:
        ca_file = self._required("KLYROW_ALERT_MTLS_CA_FILE")
        cert_file = self._required("KLYROW_ALERT_MTLS_CERT_FILE")
        key_file = self._required("KLYROW_ALERT_MTLS_KEY_FILE")
        for name, value in (
            ("KLYROW_ALERT_MTLS_CA_FILE", ca_file),
            ("KLYROW_ALERT_MTLS_CERT_FILE", cert_file),
            ("KLYROW_ALERT_MTLS_KEY_FILE", key_file),
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
            raise KlyrowAlertAdapterError(
                "Klyrow alert adapter does not own this target"
            )
        if request.command_type != self.COMMAND_TYPE:
            raise KlyrowAlertAdapterError("unsupported Klyrow alert command")
        if request.command_version != "1.0":
            raise KlyrowAlertAdapterError(
                "Klyrow alert command version must be 1.0"
            )
        if request.capability != self.CAPABILITY:
            raise KlyrowAlertAdapterError("Klyrow alert capability mismatch")

    def _validate_payload(
        self,
        request: CommandExecutionRequest,
        *,
        allow_legacy_recipient: bool = False,
    ) -> dict[str, Any]:
        self._validate_identity(request)
        payload = request.payload
        expected_keys = {
            "schema_version",
            "message_id",
            "from",
            "to",
            "reply_to",
            "content",
            "classification",
            "recipient_policy_id",
            "sender_policy_id",
            "alert",
        }
        if set(payload) != expected_keys or payload.get("schema_version") != "1.0":
            raise KlyrowAlertAdapterError(
                "observability alert payload shape is invalid"
            )
        if payload.get("message_id") != request.command_id:
            raise KlyrowAlertAdapterError(
                "provider message identity must equal command identity"
            )
        if payload.get("from") != "alerts@codestra.co":
            raise KlyrowAlertAdapterError("alert sender is not approved")
        recipient = payload.get("to")
        reply_to = payload.get("reply_to")
        active_recipient = (
            recipient == [self.ACTIVE_RECIPIENT]
            and reply_to == self.ACTIVE_RECIPIENT
        )
        legacy_recipient = (
            isinstance(recipient, list)
            and len(recipient) == 1
            and recipient[0] in self.LEGACY_READBACK_RECIPIENTS
            and reply_to == recipient[0]
        )
        if not active_recipient and not (
            allow_legacy_recipient and legacy_recipient
        ):
            raise KlyrowAlertAdapterError(
                "alert recipient or reply-to is not approved"
            )
        if payload.get("classification") != "operational-alert":
            raise KlyrowAlertAdapterError("alert classification is not approved")
        if payload.get("recipient_policy_id") != "codestra-observability-admin-v1":
            raise KlyrowAlertAdapterError("recipient policy is not approved")
        if payload.get("sender_policy_id") != "codestra-alert-sender-v1":
            raise KlyrowAlertAdapterError("sender policy is not approved")
        content = payload.get("content")
        alert = payload.get("alert")
        if not isinstance(content, dict) or set(content) != {
            "subject",
            "text",
            "html",
        }:
            raise KlyrowAlertAdapterError("alert content shape is invalid")
        if not isinstance(alert, dict) or alert.get("fingerprint") in {None, ""}:
            raise KlyrowAlertAdapterError("alert evidence is incomplete")
        for name, maximum in (
            ("subject", 1_000),
            ("text", 32_000),
            ("html", 64_000),
        ):
            value = content.get(name)
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > maximum
            ):
                raise KlyrowAlertAdapterError(
                    f"alert {name} is outside the allowed bounds"
                )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        lowered = canonical.lower()
        if (
            "authorization" in lowered
            or "-----begin " in lowered
            or "bearer " in lowered
        ):
            raise KlyrowAlertAdapterError(
                "alert payload contains prohibited secret material"
            )
        return payload

    def _require_active(
        self,
        request: CommandExecutionRequest,
        *,
        allow_legacy_recipient: bool = False,
    ) -> dict[str, Any]:
        payload = self._validate_payload(
            request,
            allow_legacy_recipient=allow_legacy_recipient,
        )
        if not self._explicit_bool("OBSERVABILITY_ALERT_EMAIL_DELIVERY"):
            raise KlyrowAlertAdapterError(
                "OBSERVABILITY_ALERT_EMAIL_DELIVERY is disabled"
            )
        activation_id = self._required("OBSERVABILITY_ALERT_ACTIVATION_ID")
        if (
            self.settings.app_env == "production"
            and self.settings.production_activation_id != activation_id
        ):
            raise KlyrowAlertAdapterError(
                "alert activation does not match production activation"
            )
        if self._explicit_bool("LIVE_EMAIL_DELIVERY"):
            raise KlyrowAlertAdapterError(
                "general LIVE_EMAIL_DELIVERY must remain disabled for the alert-only adapter"
            )
        return payload

    async def _access_token(self) -> str:
        now = time.monotonic()
        if self._token is not None and self._token[1] > now + 30:
            return self._token[0]
        async with self._token_lock:
            now = time.monotonic()
            if self._token is not None and self._token[1] > now + 30:
                return self._token[0]
            token_url = self.env.get(
                "KLYROW_ALERT_OIDC_TOKEN_URL",
                self.TOKEN_URL,
            ).strip()
            if token_url != self.TOKEN_URL:
                raise ConfigurationError(
                    "KLYROW alert token URL must use the canonical issuer"
                )
            client_id = self.env.get(
                "KLYROW_ALERT_OIDC_CLIENT_ID",
                self.CLIENT_ID,
            ).strip()
            if client_id != self.CLIENT_ID:
                raise ConfigurationError("KLYROW alert client ID is not approved")
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
                            "KLYROW_ALERT_OIDC_CLIENT_SECRET_FILE"
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
                raise KlyrowAlertAdapterError(
                    "Klyrow alert access token is missing"
                )
            if (
                isinstance(expires_in, bool)
                or not isinstance(expires_in, int)
                or not 30 <= expires_in <= 900
            ):
                raise KlyrowAlertAdapterError(
                    "Klyrow alert token lifetime is invalid"
                )
            self._token = (token, time.monotonic() + min(expires_in, 300))
            return token

    async def _headers(
        self,
        request: CommandExecutionRequest,
    ) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": "Bearer " + await self._access_token(),
            "Content-Type": "application/json",
            "X-Tenant-ID": request.tenant_id,
            "X-Correlation-ID": request.correlation_id,
            "Idempotency-Key": request.idempotency_key,
            "X-Codestra-Classification": "operational-alert",
        }

    @staticmethod
    def _provider_document(
        request: CommandExecutionRequest,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "message_id": request.command_id,
            "tenant_id": request.tenant_id,
            "sender": payload["from"],
            "recipients": payload["to"],
            "reply_to": payload["reply_to"],
            "subject": payload["content"]["subject"],
            "text": payload["content"]["text"],
            "html": payload["content"]["html"],
            "stream": "operational",
            "classification": payload["classification"],
            "recipient_policy_id": payload["recipient_policy_id"],
            "sender_policy_id": payload["sender_policy_id"],
            "metadata": {
                "alert_fingerprint": payload["alert"]["fingerprint"],
                "alert_state": payload["alert"]["state"],
                "severity": payload["alert"]["severity"],
                "service": payload["alert"]["service"],
                "host": payload["alert"]["host"],
                "environment": payload["alert"]["environment"],
                "release_id": payload["alert"]["labels"].get(
                    "release_id",
                    "",
                ),
            },
        }

    async def execute(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        payload = self._require_active(
            request,
            allow_legacy_recipient=True,
        )
        if payload["to"][0] in self.LEGACY_READBACK_RECIPIENTS:
            reconciled = await self.readback(request)
            if reconciled.status == "matched":
                return ActivityResult(
                    status="accepted",
                    detail=(
                        "Legacy alert payload was not resubmitted; "
                        "provider read-back confirmed its prior acceptance"
                    ),
                    provider_operation_id=request.command_id,
                )
            raise KlyrowAlertAdapterError(
                "legacy queued alert requires controlled reissue "
                "to the active recipient"
            )
        body = self._provider_document(request, payload)
        try:
            async with httpx.AsyncClient(
                verify=self._tls_context(),
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    self._base_url() + self.MESSAGE_PATH,
                    json=body,
                    headers=await self._headers(request),
                )
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError, ConfigurationError) as exc:
            try:
                reconciled = await self.readback(request)
            except KlyrowAlertAdapterError as readback_error:
                raise KlyrowAlertAdapterError(
                    "Klyrow alert outcome remains unknown after read-back failed"
                ) from readback_error
            if reconciled.status == "matched":
                return ActivityResult(
                    status="accepted",
                    detail=(
                        "Klyrow write response was interrupted; "
                        "read-back confirmed acceptance"
                    ),
                    provider_operation_id=request.command_id,
                )
            raise KlyrowAlertAdapterError(
                "Klyrow alert submission failed"
            ) from exc
        provider_id = None
        if isinstance(value, dict):
            provider_id = (
                value.get("message_id")
                or value.get("operation_id")
                or value.get("id")
            )
        if str(provider_id or "") != request.command_id:
            raise KlyrowAlertAdapterError(
                "Klyrow response did not bind the command identity"
            )
        return ActivityResult(
            status="accepted",
            detail="Klyrow accepted the fixed-recipient observability alert",
            provider_operation_id=request.command_id,
        )

    async def readback(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        payload = self._validate_payload(
            request,
            allow_legacy_recipient=True,
        )
        path = self.MESSAGE_STATUS_PATH.format(
            message_id=quote(request.command_id, safe="")
        )
        try:
            async with httpx.AsyncClient(
                verify=self._tls_context(),
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    self._base_url() + path,
                    headers=await self._headers(request),
                )
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError, ConfigurationError) as exc:
            raise KlyrowAlertAdapterError(
                "Klyrow alert read-back failed"
            ) from exc
        if not isinstance(value, dict):
            raise KlyrowAlertAdapterError(
                "Klyrow alert read-back is malformed"
            )
        provider_id = (
            value.get("message_id")
            or value.get("operation_id")
            or value.get("id")
        )
        recipient = value.get("recipient") or value.get("to")
        sender = value.get("sender") or value.get("from")
        status_value = str(value.get("status") or "").lower()
        if isinstance(recipient, str):
            recipient_matches = recipient == payload["to"][0]
        elif isinstance(recipient, list):
            recipient_matches = recipient == payload["to"]
        else:
            recipient_matches = False
        if (
            str(provider_id or "") == request.command_id
            and recipient_matches
            and sender == payload["from"]
            and status_value
            in {"accepted", "queued", "sending", "sent", "delivered"}
        ):
            return ActivityResult(
                status="matched",
                detail=(
                    "Klyrow read-back matched the fixed-recipient alert intent"
                ),
                provider_operation_id=request.command_id,
                readback_evidence={
                    "schema_version": "1.0",
                    "message_id": request.command_id,
                    "status": status_value,
                    "recipient_policy_id": payload["recipient_policy_id"],
                    "sender_policy_id": payload["sender_policy_id"],
                },
            )
        return ActivityResult(
            status="mismatch",
            detail=(
                "Klyrow read-back did not match the fixed-recipient alert intent"
            ),
            provider_operation_id=request.command_id,
        )
