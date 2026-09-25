"""Private service API bridges; all effects run through the V3 worker.

Bindings and short-lived workload JWT suppliers are injected by the runtime.
No service is activated by importing this module or by a connector manifest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Awaitable, Callable
from urllib.parse import quote, urlsplit

import httpx

from app.commands import CommandEnvelope, CommandOperation
from app.identity_service_contract import (
    REFERENCE,
    SERVICE_COMMANDS,
    validate_service_command,
)
from app.identity_missions import (
    MISSION_COMMANDS,
    MISSION_RESULTS,
    READBACKS,
    SERVICE_READBACKS,
    validate_schema,
    validate_event_idempotency,
)
from app.platform.adapter import (
    AdapterConfigurationError,
    AdapterContext,
    AdapterReadiness,
    AdapterResult,
    BaseAdapter,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)


def payload_digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


class IdentityServiceAdapter(BaseAdapter):
    """One contract shared by four independently owned service APIs.

    ``token_supplier(audience, scope, tenant_id)`` resolves workload credentials only in
    the worker. The service must validate signature/JWKS, issuer, audience,
    expiry, caller and tenant; forwarding an ingress bearer token is forbidden.
    """

    supports_status = True

    def __init__(
        self,
        service_id: str,
        *,
        origin: str,
        token_supplier: Callable[[str, str, str], Awaitable[str]],
    ) -> None:
        if service_id not in SERVICE_COMMANDS:
            raise AdapterConfigurationError("unknown service")
        self.adapter_id = self.provider_family = service_id
        self.connector_ids = (service_id,)
        self.served_capabilities = tuple(
            dict.fromkeys(
                [
                    SERVICE_COMMANDS[service_id][0],
                    *(
                        value[0]
                        for name, value in MISSION_COMMANDS.items()
                        if name.split(".", 1)[0] == service_id
                    ),
                ]
            )
        )
        self.origin = origin
        self.token_supplier = token_supplier
        self.validate_config()

    def validate_config(self) -> None:
        super().validate_config()
        url = urlsplit(self.origin)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
        ):
            raise AdapterConfigurationError(
                "binding must be a verified HTTPS origin without credentials or path"
            )
        if not callable(self.token_supplier):
            raise AdapterConfigurationError("workload JWT supplier required")

    async def _request(
        self,
        context: AdapterContext,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        key: str | None = None,
    ) -> httpx.Response:
        if context.http is None:
            raise AdapterConfigurationError("shared HTTP client required")
        scope = (
            f"connector.{self.adapter_id}.{'command' if method == 'POST' else 'read'}"
        )
        token = await self.token_supplier(self.adapter_id, scope, context.tenant_id)
        if not token or any(c.isspace() for c in token):
            raise AdapterConfigurationError("workload JWT unavailable")
        headers = {
            **context.outbound_headers(),
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": context.tenant_id,
        }
        if key is not None:
            headers["Idempotency-Key"] = key
        return await context.http.request(
            method,
            self.origin + path,
            headers=headers,
            json=payload,
            timeout=context.timeout_seconds,
            follow_redirects=False,
        )

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        try:
            response = await self._request(context, "GET", "/health/ready")
            return AdapterReadiness(response.status_code == 200, "service_health")
        except Exception:  # A failed probe must never make a service ready.
            return AdapterReadiness(False, "service_unavailable")

    async def execute(
        self, command: CommandEnvelope, context: AdapterContext
    ) -> AdapterResult:
        try:
            validate_service_command(
                command.command_type,
                command.target,
                command.capability,
                command.payload,
            )
            validate_event_idempotency(
                command.command_type, command.payload, command.idempotency_key
            )
            valid = True
        except ValueError:
            valid = False
        if (
            not valid
            or command.target != self.adapter_id
            or context.tenant_id != command.tenant_id
            or context.command_id != str(command.command_id)
        ):
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="service_contract_invalid",
            )
        body = command.model_dump(mode="json")
        body["payload_sha256"] = payload_digest(command.payload)
        try:
            response = await self._request(
                context,
                "POST",
                "/internal/v1/commands",
                payload=body,
                key=command.idempotency_key,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return AdapterResult(
                Outcome.TRANSIENT,
                error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT,
                safe_error_code="connect_failed",
            )
        except AdapterConfigurationError:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.NON_RETRYABLE,
                safe_error_code="binding_unavailable",
            )
        except Exception:
            return AdapterResult(
                Outcome.UNKNOWN,
                error_class=ErrorClass.AMBIGUOUS,
                safe_error_code="submission_unknown",
            )
        if response.status_code in {200, 202}:
            try:
                raw = response.json()
                reference = raw["operation_id"]
                if (
                    raw["command_id"] == str(command.command_id)
                    and raw["tenant_id"] == command.tenant_id
                    and isinstance(reference, str)
                    and REFERENCE.fullmatch(reference)
                ):
                    return AdapterResult(
                        Outcome.ACCEPTED, provider_operation_id=reference
                    )
            except (ValueError, KeyError, TypeError):
                pass
        # These statuses contractually guarantee rejection before any effect.
        if response.status_code in {400, 401, 403, 409, 422}:
            return AdapterResult(
                Outcome.REJECTED,
                error_class=ErrorClass.PROVIDER_AUTH
                if response.status_code in {401, 403}
                else ErrorClass.NON_RETRYABLE,
                safe_error_code=f"service_http_{response.status_code}",
            )
        # Including 429/503: absent proof of no effect, never blindly retry.
        return AdapterResult(
            Outcome.UNKNOWN,
            error_class=ErrorClass.AMBIGUOUS,
            safe_error_code="submission_unknown",
        )

    async def readback(
        self, operation: CommandOperation, context: AdapterContext
    ) -> ReadbackResult:
        if (
            context.tenant_id != operation.tenant_id
            or context.command_id != str(operation.command_id)
            or operation.target != self.adapter_id
        ):
            return ReadbackResult(
                ReadbackStatus.MISMATCH, safe_error_code="identity_mismatch"
            )
        try:
            # Lookup by canonical command id also recovers a lost acknowledgement.
            response = await self._request(
                context,
                "GET",
                f"/internal/v1/commands/{quote(str(operation.command_id), safe='')}",
            )
            if response.status_code == 404:
                return ReadbackResult(ReadbackStatus.NOT_FOUND)
            if response.status_code != 200:
                return ReadbackResult(ReadbackStatus.UNAVAILABLE)
            raw = response.json()
            expected = {
                "command_id": str(operation.command_id),
                "tenant_id": operation.tenant_id,
                "command_type": operation.command_type,
                "idempotency_key": operation.idempotency_key,
                "payload_sha256": payload_digest(dict(context.payload)),
            }
            if any(raw.get(k) != v for k, v in expected.items()):
                return ReadbackResult(
                    ReadbackStatus.MISMATCH, safe_error_code="readback_binding_mismatch"
                )
            reference = raw.get("operation_id")
            if (
                not isinstance(reference, str)
                or not REFERENCE.fullmatch(reference)
                or (
                    operation.provider_operation_id
                    and reference != operation.provider_operation_id
                )
            ):
                return ReadbackResult(
                    ReadbackStatus.MISMATCH, safe_error_code="operation_mismatch"
                )
            result = {}
            if (
                raw.get("state") == "completed"
                and operation.command_type in MISSION_RESULTS
            ):
                result = raw.get("result")
                validate_schema(MISSION_RESULTS[operation.command_type], result)
                for field in (
                    "event_ref",
                    "camera_ref",
                    "watchlist_ref",
                    "subject_ref",
                    "session_ref",
                    "review_ref",
                ):
                    if (
                        field in result
                        and field in context.payload
                        and result[field] != context.payload[field]
                    ):
                        return ReadbackResult(ReadbackStatus.MISMATCH)
            status = {
                "completed": ReadbackStatus.MATCHED,
                "failed": ReadbackStatus.MISMATCH,
            }.get(raw.get("state"), ReadbackStatus.UNAVAILABLE)
            return ReadbackResult(
                status,
                provider_operation_id=reference,
                evidence={"payload_sha256": expected["payload_sha256"], **result},
            )
        except Exception:
            return ReadbackResult(
                ReadbackStatus.UNAVAILABLE, safe_error_code="readback_unavailable"
            )

    async def read_observability(
        self, name: str, database_ref: str, context: AdapterContext
    ) -> ReadbackResult:
        """Fixed GET-only projections; never a caller-supplied URL or SQL query."""
        contract = READBACKS.get(name)
        if (
            self.adapter_id != "postgresql"
            or contract is None
            or not REFERENCE.fullmatch(database_ref)
            or not REFERENCE.fullmatch(context.tenant_id)
        ):
            return ReadbackResult(ReadbackStatus.MISMATCH)
        try:
            response = await self._request(
                context, "GET", contract["path"] + "/" + database_ref
            )
            if response.status_code != 200:
                return ReadbackResult(ReadbackStatus.UNAVAILABLE)
            raw = response.json()
            validate_schema(contract["schema"], raw)
            if (
                raw["tenant_id"] != context.tenant_id
                or raw["database_ref"] != database_ref
            ):
                return ReadbackResult(ReadbackStatus.MISMATCH)
            return ReadbackResult(ReadbackStatus.MATCHED, evidence=raw)
        except Exception:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE)

    async def read_service_evidence(
        self,
        name: str,
        resource_ref: str | None,
        context: AdapterContext,
    ) -> ReadbackResult:
        """Read one fixed, tenant-bound service evidence contract.

        Paths come only from SERVICE_READBACKS. Callers can supply an opaque
        resource reference where the contract explicitly declares one; they
        can never supply a URL, path, query string, secret, or arbitrary
        service identifier.
        """
        contract = SERVICE_READBACKS.get(name)
        if (
            contract is None
            or self.adapter_id != contract["service_id"]
            or not REFERENCE.fullmatch(context.tenant_id)
        ):
            return ReadbackResult(ReadbackStatus.MISMATCH)
        resource_param = contract["resource_param"]
        path = contract["path"]
        if resource_param is None:
            if resource_ref is not None:
                return ReadbackResult(ReadbackStatus.MISMATCH)
        else:
            if resource_ref is None or not REFERENCE.fullmatch(resource_ref):
                return ReadbackResult(ReadbackStatus.MISMATCH)
            token = "{" + resource_param + "}"
            if token not in path:
                return ReadbackResult(ReadbackStatus.MISMATCH)
            path = path.replace(token, quote(resource_ref, safe=""))
        try:
            response = await self._request(context, "GET", path)
            if response.status_code == 404:
                return ReadbackResult(ReadbackStatus.NOT_FOUND)
            if response.status_code != 200:
                return ReadbackResult(ReadbackStatus.UNAVAILABLE)
            raw = response.json()
            validate_schema(contract["schema"], raw)
            if resource_ref is not None:
                if "camera_id" in raw and raw["camera_id"] != resource_ref:
                    return ReadbackResult(ReadbackStatus.MISMATCH)
                if name == "camera-event-page" and any(
                    item.get("camera_id") != resource_ref for item in raw["items"]
                ):
                    return ReadbackResult(ReadbackStatus.MISMATCH)
            return ReadbackResult(ReadbackStatus.MATCHED, evidence=raw)
        except Exception:
            return ReadbackResult(
                ReadbackStatus.UNAVAILABLE,
                safe_error_code="service_evidence_unavailable",
            )

    async def status(
        self, operation: CommandOperation, context: AdapterContext
    ) -> AdapterResult:
        result = await self.readback(operation, context)
        outcome = (
            Outcome.COMPLETED
            if result.status == ReadbackStatus.MATCHED
            else Outcome.UNKNOWN
        )
        return AdapterResult(
            outcome, provider_operation_id=result.provider_operation_id
        )
