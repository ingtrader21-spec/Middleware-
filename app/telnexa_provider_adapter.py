from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from collections.abc import Mapping
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator, FormatChecker

from app.core.config import ConfigurationError
from .temporal_workflows import ActivityResult, CommandExecutionRequest


ROOT = Path(__file__).resolve().parents[1]
TELNEXA_SMS_COMMAND_SCHEMA = ROOT / "contracts" / "telnexa-sms-command.v1.schema.json"


class TelnexaProviderAdapterError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _telnexa_sms_command_validator() -> Draft202012Validator:
    """Enforce the local SMS specialization without resolving its remote base ref."""
    try:
        source = json.loads(TELNEXA_SMS_COMMAND_SCHEMA.read_text(encoding="utf-8"))
        specialization = source["allOf"][1]
        local_schema = {**specialization, "$defs": source.get("$defs", {})}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, IndexError) as exc:
        raise TelnexaProviderAdapterError(
            "canonical Telnexa SMS command schema cannot be loaded"
        ) from exc
    Draft202012Validator.check_schema(local_schema)
    return Draft202012Validator(local_schema, format_checker=FormatChecker())


class TelnexaSmsAdapter:
    """Submit through Telnexa; reconcile only through its non-submitting GET API.

    Middleware never speaks to Jasmin or an SMSC. A missing/invalid read-back
    remains unconfirmed and never causes another POST, even after a timeout or
    with delivery disabled. Durable command identity is Telnexa's message_id,
    not a carrier-local ID. A matched record proves acceptance, not delivery.
    """

    SUBMIT_SMS = "sms.message.submit.v1"
    SUPPORTED = frozenset({SUBMIT_SMS})
    MESSAGES_PATH = "/api/v1/messages"
    READBACK_PATH = MESSAGES_PATH + "/by-idempotency"
    READBACK_VERSION = "telnexa.sms.readback.v1"
    ACCEPTED_STATUSES = frozenset({200, 202})
    IDEMPOTENCY_CONFLICT = "idempotency_key_payload_mismatch"
    MATCHED_STATES = frozenset({"accepted", "queued", "submitted", "sent", "delivered"})
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
        self, settings: Any, env: Mapping[str, str] | None = None
    ) -> None:
        self.settings = settings
        self.env = os.environ if env is None else env

    def _required(self, name: str) -> str:
        value = self.env.get(name, "").strip()
        if not value:
            raise ConfigurationError(f"{name} is required for the Telnexa adapter")
        return value

    def _base_url(self) -> str:
        value = self._required("TELNEXA_SMS_BASE_URL").rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("TELNEXA_SMS_BASE_URL must be an HTTP(S) origin")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path
        ):
            raise ConfigurationError(
                "TELNEXA_SMS_BASE_URL must be a credential-free origin"
            )
        app_env = self.env.get("APP_ENV", getattr(self.settings, "app_env", "development")).strip().lower()
        if app_env == "production" and parsed.scheme != "https":
            raise ConfigurationError("production Telnexa delivery requires HTTPS")
        return value

    def _api_key(self) -> str:
        return self._required("TELNEXA_SMS_API_KEY")

    def _validate_identity(self, request: CommandExecutionRequest) -> None:
        if request.target != "telnexa-sms":
            raise TelnexaProviderAdapterError(
                "Telnexa adapter does not own this command target"
            )
        if request.capability != "SMS_DELIVERY":
            raise TelnexaProviderAdapterError(
                "Telnexa command capability must be SMS_DELIVERY"
            )
        if request.command_type not in self.SUPPORTED:
            raise TelnexaProviderAdapterError(
                f"unsupported Telnexa command type: {request.command_type}"
            )
        if request.command_version != "1.0":
            raise TelnexaProviderAdapterError("Telnexa command version must be 1.0")
        for name, value, limit in (
            ("idempotency_key", request.idempotency_key, 180),
            ("correlation_id", request.correlation_id, 36),
        ):
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= limit
                or not value.isascii()
                or any(ord(char) < 33 or ord(char) > 126 for char in value)
            ):
                raise TelnexaProviderAdapterError(
                    f"Telnexa {name} violates its bounded contract"
                )

    def _require_active(self, request: CommandExecutionRequest) -> None:
        self._validate_identity(request)
        if not self.settings.sms_delivery_enabled:
            raise TelnexaProviderAdapterError(
                "SMS delivery is disabled by SMS_DELIVERY_ENABLED or its umbrella "
                "switch EXTERNAL_DELIVERY_ENABLED"
            )
        error = next(
            iter(
                _telnexa_sms_command_validator().iter_errors(
                    {
                        "command_id": request.command_id,
                        "command_type": request.command_type,
                        "command_version": request.command_version,
                        "target": request.target,
                        "tenant_id": request.tenant_id,
                        "requested_by": request.requested_by,
                        "correlation_id": request.correlation_id,
                        "idempotency_key": request.idempotency_key,
                        "capability": request.capability,
                        "payload": request.payload,
                    }
                )
            ),
            None,
        )
        if error is not None:
            raise TelnexaProviderAdapterError(
                "Telnexa SMS command violates its canonical contract"
            )

    def _submission(self, request: CommandExecutionRequest) -> dict[str, Any]:
        """Project onto Telnexa's request; Telnexa alone computes segments/rating."""
        payload = request.payload
        if self.FORBIDDEN_PAYLOAD_KEYS.intersection(payload):
            raise TelnexaProviderAdapterError(
                "command payload carries forbidden secret keys"
            )
        account = payload.get("billing_account_id")
        if not isinstance(account, str) or not 1 <= len(account) <= 36:
            raise TelnexaProviderAdapterError(
                "Telnexa requires bounded billing_account_id on the SMS command"
            )
        try:
            submission = {
                "billing_account_id": account,
                "destination": payload["destination"],
                "sender": payload["sender"],
                "content": payload["content"],
                "category": payload["category"],
            }
        except KeyError as exc:
            raise TelnexaProviderAdapterError("incomplete Telnexa SMS command") from exc
        for field in ("campaign_id", "client_reference"):
            value = payload.get(field)
            if isinstance(value, str) and value:
                submission[field] = value
        return submission

    def _headers(self, request: CommandExecutionRequest) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key(),
            "X-Tenant-ID": request.tenant_id,
            "X-Correlation-ID": request.correlation_id,
            "Idempotency-Key": request.idempotency_key,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _error_code(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except (ValueError, RecursionError):
            return "unparseable-response"
        if isinstance(payload, dict):
            value = payload.get("detail", payload.get("error"))
            if (
                isinstance(value, str)
                and 0 < len(value) <= 80
                and all(
                    char in "abcdefghijklmnopqrstuvwxyz0123456789_:-" for char in value
                )
            ):
                return value
        return "unspecified"

    @staticmethod
    def _provider_message_id(data: Any) -> str | None:
        if not isinstance(data, dict):
            return None
        value = data.get("message_id")
        if isinstance(value, str) and 0 < len(value) <= 36 and value.isascii():
            return value
        return None

    @staticmethod
    def _request_hash(submission: dict[str, Any]) -> str:
        # Match SendRequest.model_dump: optional absent fields are null and
        # json.dumps uses sorted compact keys and default ASCII escaping.
        normalized = {"campaign_id": None, "client_reference": None, **submission}
        return hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    async def _submit(
        self, request: CommandExecutionRequest, submission: dict[str, Any]
    ) -> httpx.Response:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=False) as client:
            return await client.post(
                f"{self._base_url()}{self.MESSAGES_PATH}",
                json=submission,
                headers=self._headers(request),
            )

    async def execute(self, request: CommandExecutionRequest) -> ActivityResult:
        self._require_active(request)
        submission = self._submission(request)
        try:
            response = await self._submit(request, submission)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise TelnexaProviderAdapterError(
                "Telnexa connection failed before the submission was sent"
            ) from exc
        except httpx.HTTPError:
            return await self._reconcile_unknown_submission(
                request, "transport outcome unconfirmed"
            )
        if response.status_code in self.ACCEPTED_STATUSES:
            try:
                message_id = self._provider_message_id(response.json())
            except (ValueError, RecursionError):
                message_id = None
            if message_id is None:
                return await self._reconcile_unknown_submission(
                    request, "acceptance body unconfirmed"
                )
            return ActivityResult(
                status="accepted",
                detail="Telnexa accepted the canonical SMS submission",
                provider_operation_id=message_id,
            )
        if response.status_code >= 500:
            return await self._reconcile_unknown_submission(
                request, "gateway outcome unconfirmed"
            )
        raise TelnexaProviderAdapterError(
            f"Telnexa rejected the submission with status {response.status_code}: {self._error_code(response)}"
        )

    async def _reconcile_unknown_submission(
        self, request: CommandExecutionRequest, reason: str
    ) -> ActivityResult:
        result = await self.readback(request)
        if result.status == "matched":
            return ActivityResult(
                status="accepted",
                detail=f"Telnexa outcome was unknown ({reason}); read-only GET confirmed durable acceptance",
                provider_operation_id=result.provider_operation_id,
            )
        raise TelnexaProviderAdapterError(
            f"Telnexa outcome unknown ({reason}); {result.detail}"
        )

    async def readback(self, request: CommandExecutionRequest) -> ActivityResult:
        """Read only; never submit, follow redirects or guess a missing identity."""
        self._validate_identity(request)
        submission = self._submission(request)
        try:
            async with httpx.AsyncClient(
                timeout=25.0, follow_redirects=False
            ) as client:
                response = await client.get(
                    f"{self._base_url()}{self.READBACK_PATH}",
                    headers=self._headers(request),
                )
        except httpx.HTTPError as exc:
            raise TelnexaProviderAdapterError(
                "Telnexa read-only reconciliation failed"
            ) from exc
        if response.status_code == 200 and len(response.content) <= 65536:
            try:
                data = response.json()
            except (ValueError, RecursionError):
                data = None
            message_id = self._provider_message_id(data)
            if (
                message_id
                and isinstance(data, dict)
                and data.get("contract_version") == self.READBACK_VERSION
                and data.get("tenant_id") == request.tenant_id
                and data.get("idempotency_key") == request.idempotency_key
                and data.get("request_hash") == self._request_hash(submission)
                and data.get("correlation_id") == request.correlation_id
                and isinstance(data.get("status"), str)
                and data.get("status") in self.MATCHED_STATES
                and data.get("submission_certainty") != "unknown"
            ):
                return ActivityResult(
                    status="matched",
                    detail="Read-only GET matched durable Telnexa acceptance; carrier delivery is not implied",
                    provider_operation_id=message_id,
                )
            detail = (
                "Telnexa read-back identity, fingerprint or outcome was not confirmed"
            )
        elif (
            response.status_code == 409
            and self._error_code(response) == self.IDEMPOTENCY_CONFLICT
        ):
            detail = (
                "the idempotency key is already bound to a different Telnexa submission"
            )
        else:
            detail = f"Telnexa read-only reconciliation returned status {response.status_code}; no resubmission"
        return ActivityResult(
            status="mismatch", detail=detail, provider_operation_id=None
        )
