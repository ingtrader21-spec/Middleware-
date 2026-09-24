"""The provider adapters, as bridges over the transports main already owns.

Odoo (:mod:`app.odoo_provider_adapter` + :mod:`app.adapters.odoo.crm_bridge_client`),
Klyrow email (:mod:`app.klyrow_email_adapter`), Telnexa SMS
(:mod:`app.telnexa_provider_adapter`), bounded VICIdial calling
(:mod:`app.vicidial_internal_call_adapter`) and Postly social publishing
(:mod:`app.postly_social_adapter`) already implement the provider-specific
transport, signing, schema validation and read-back-before-retry rules for
the Temporal activities. Nothing about those transports is rewritten here:
each bridge maps a :class:`~app.commands.CommandEnvelope` onto the legacy
``CommandExecutionRequest``, classifies the legacy ``ActivityResult`` into the
kernel's outcome classes and exposes ``readback``/``reconcile``.

A provider adapter is registered only when its configuration validates
(``validate_config``); an unconfigured provider leaves its capability
unavailable, which the Safety Gate reports as ``adapter_not_registered``.
Every external-effect capability is ``false`` in ``config/capabilities.v2.json``
regardless: registering an adapter never activates an effect.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping

import httpx

from app.commands import CommandEnvelope, CommandOperation
from app.core.config import Settings
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
    classify_status,
)

logger = logging.getLogger("codestra.platform.adapters.providers")

# Legacy ActivityResult.status -> kernel outcome. Legacy adapters already read
# back on transport failure and only answer "accepted" when the provider
# confirmed, so "accepted" is an acknowledgement (readback decides completion).
_EXECUTE_OUTCOMES: Mapping[str, Outcome] = {
    "accepted": Outcome.ACCEPTED,
    "completed": Outcome.COMPLETED,
    "matched": Outcome.COMPLETED,
    "delivered": Outcome.COMPLETED,
    "rejected": Outcome.REJECTED,
    "mismatch": Outcome.REJECTED,
    "failed": Outcome.REJECTED,
    "pending": Outcome.UNKNOWN,
    "readback_pending": Outcome.UNKNOWN,
    "dispatch_unknown": Outcome.UNKNOWN,
    "unknown": Outcome.UNKNOWN,
}
_READBACK_STATUSES: Mapping[str, ReadbackStatus] = {
    "matched": ReadbackStatus.MATCHED,
    "completed": ReadbackStatus.MATCHED,
    "delivered": ReadbackStatus.MATCHED,
    "accepted": ReadbackStatus.MATCHED,
    "mismatch": ReadbackStatus.MISMATCH,
    "rejected": ReadbackStatus.MISMATCH,
    "failed": ReadbackStatus.MISMATCH,
    "not_found": ReadbackStatus.NOT_FOUND,
    "missing": ReadbackStatus.NOT_FOUND,
    "pending": ReadbackStatus.UNAVAILABLE,
    "readback_pending": ReadbackStatus.UNAVAILABLE,
    "dispatch_unknown": ReadbackStatus.UNAVAILABLE,
    "unknown": ReadbackStatus.UNAVAILABLE,
}


class LegacyProviderAdapter:
    """The surface the Temporal activities already program against."""

    async def execute(self, request: Any) -> Any: ...

    async def readback(self, request: Any) -> Any: ...


def _execution_request(command: CommandEnvelope | CommandOperation, *, client_id: str, payload: Mapping[str, Any]) -> Any:
    from app.temporal_workflows import CommandExecutionRequest

    return CommandExecutionRequest(
        command_id=str(command.command_id),
        command_type=command.command_type,
        command_version=command.command_version,
        target=command.target,
        tenant_id=command.tenant_id,
        requested_by=command.requested_by,
        correlation_id=command.correlation_id,
        idempotency_key=command.idempotency_key,
        capability=command.capability,
        payload=dict(payload),
        authenticated_client_id=client_id,
    )


def _activity_status(raw: Any) -> tuple[str, str | None, dict[str, Any]]:
    status = str(getattr(raw, "status", "unknown")).lower()
    reference = getattr(raw, "provider_operation_id", None)
    evidence = getattr(raw, "readback_evidence", None)
    return status, reference if isinstance(reference, str) else None, dict(evidence) if isinstance(evidence, Mapping) else {}


@dataclass
class LegacyBridge(BaseAdapter):
    """Generic bridge: one legacy adapter, a set of supported command types."""

    adapter_id: str = ""
    provider_family: str = ""
    connector_ids: tuple[str, ...] = ()
    served_capabilities: tuple[str, ...] = ()
    version: str = "legacy-bridge/2.0"
    legacy: Any = None
    supported_command_types: frozenset[str] = frozenset()
    required_settings: tuple[str, ...] = ()
    transient_errors: tuple[type[BaseException], ...] = ()
    rejected_errors: tuple[type[BaseException], ...] = ()
    readiness_probe: Callable[[], Awaitable[bool]] | None = None
    supports_cancel: bool = False
    supports_status: bool = True
    safe_reexecution: bool = False
    external_effect: bool = True
    # The envelope payload is persisted with the authenticated client; the
    # bridge needs it for the legacy provenance checks.
    client_id_of: Callable[[CommandEnvelope | CommandOperation], str] = field(default=lambda command: "middleware-worker")

    def validate_config(self) -> None:
        BaseAdapter.validate_config(self)
        if self.legacy is None or not all(callable(getattr(self.legacy, name, None)) for name in ("execute", "readback")):
            raise AdapterConfigurationError(f"{self.adapter_id}: legacy adapter must implement execute and readback")
        if self.required_settings:
            # The legacy adapter holds its own configuration mapping; the bridge
            # never reads the process environment.
            source = getattr(self.legacy, "env", {})
            missing = [name for name in self.required_settings if not str(source.get(name, "")).strip()]
            if missing:
                raise AdapterConfigurationError(f"{self.adapter_id}: required configuration missing: {', '.join(missing)}")

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        if self.readiness_probe is None:
            return AdapterReadiness(ready=True, detail="configured")
        try:
            return AdapterReadiness(ready=bool(await self.readiness_probe()), detail="probed")
        except Exception as exc:  # noqa: BLE001 - readiness never raises
            return AdapterReadiness(ready=False, detail=type(exc).__name__)

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        if self.supported_command_types and command.command_type not in self.supported_command_types:
            return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="unsupported_command_type")
        request = _execution_request(command, client_id=self.client_id_of(command), payload=command.payload)
        try:
            raw = await self.legacy.execute(request)
        except self.rejected_errors as exc:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code=type(exc).__name__)
        except self.transient_errors as exc:
            return AdapterResult(Outcome.TRANSIENT, error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT, safe_error_code=type(exc).__name__)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return AdapterResult(Outcome.TRANSIENT, error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT, safe_error_code=type(exc).__name__)
        except Exception as exc:  # noqa: BLE001 - the provider outcome is unknown; the kernel reads back
            logger.warning("legacy adapter %s raised %s", self.adapter_id, type(exc).__name__)
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        return self.normalize_result(raw)

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        readback = await self.readback(operation, context)
        if readback.status is ReadbackStatus.MATCHED:
            return AdapterResult(Outcome.COMPLETED, provider_operation_id=readback.provider_operation_id)
        if readback.status is ReadbackStatus.MISMATCH:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="readback_mismatch")
        return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=readback.safe_error_code)

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        request = _execution_request(operation, client_id=self.client_id_of(operation), payload=context.payload)
        try:
            raw = await self.legacy.readback(request)
        except Exception as exc:  # noqa: BLE001 - still unknown; the kernel keeps the operation open
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        status, reference, evidence = _activity_status(raw)
        return ReadbackResult(
            _READBACK_STATUSES.get(status, ReadbackStatus.UNAVAILABLE),
            provider_operation_id=reference or operation.provider_operation_id,
            evidence=self.redact(evidence),
            safe_error_code=None if status in {"matched", "completed", "delivered", "accepted"} else f"readback_{status}",
        )

    def normalize_result(self, raw: Any) -> AdapterResult:
        if isinstance(raw, AdapterResult):
            return raw
        if not hasattr(raw, "status"):
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="unnormalizable_result")
        status, reference, _ = _activity_status(raw)
        outcome = _EXECUTE_OUTCOMES.get(status, Outcome.UNKNOWN)
        return AdapterResult(
            outcome,
            provider_operation_id=reference,
            error_class=(
                None
                if outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}
                else ErrorClass.AMBIGUOUS
                if outcome is Outcome.UNKNOWN
                else ErrorClass.NON_RETRYABLE
            ),
            safe_error_code=None if outcome in {Outcome.ACCEPTED, Outcome.COMPLETED} else f"provider_{status}",
            safe_details={"legacy_status": status},
        )


# --- Odoo: the legacy lead upsert plus the CRM bridge surfaces of #286 -----------------

CRM_BRIDGE_COMMANDS = {
    "crm.contact.create.v1": ("create_contact", None),
    "crm.contact.update.v1": ("update_contact", "contact_id"),
    "crm.note.create.v1": ("create_note", "contact_id"),
    "crm.note.update.v1": ("update_note", "note_id"),
    "crm.task.create.v1": ("create_task", "contact_id"),
    "crm.task.update.v1": ("update_task", "task_id"),
    "crm.task.complete.v1": ("complete_task", "task_id"),
    "crm.opportunity.create.v1": ("create_opportunity", None),
    "crm.opportunity.update.v1": ("update_opportunity", "external_id"),
    "crm.ticket.create.v1": ("create_ticket", None),
    "crm.ticket.update.v1": ("update_ticket", "ticket_id"),
}
CRM_READBACK = {
    "contact": ("get_contact", "profile_id", int),
    "opportunity": ("get_opportunity", "external_id", str),
    "ticket": ("get_ticket", "ticket_id", int),
}
# Notes and tasks have no GET-by-id on the bridge: the parent profile's list
# is the read surface. (reader, id key, list fields the readback compares.)
CRM_LIST_READBACK = {
    "note": ("list_notes", "note_id", ("body",)),
    "task": ("list_tasks", "task_id", ("summary", "due_date")),
}
PARENT_REFERENCE_SEPARATOR = "@"


@dataclass
class OdooAdapter(LegacyBridge):
    """``crm.lead.upsert`` through the legacy signed command transport; the
    CRM record surfaces (contacts, notes, tasks, opportunities, tickets)
    through the signed CRM bridge client of PR #286. Readback: the bridge's
    GET by id (contact/opportunity/ticket) or the legacy status route."""

    adapter_id: str = "odoo-19"
    provider_family: str = "odoo"
    connector_ids: tuple[str, ...] = ("odoo-19",)
    served_capabilities: tuple[str, ...] = ("ODOO_WRITE",)
    crm_bridge: Any = None  # OdooCrmBridgeClient | None
    supports_status: bool = True

    def validate_config(self) -> None:
        if self.legacy is None and self.crm_bridge is None:
            raise AdapterConfigurationError("odoo-19: neither the lead transport nor the CRM bridge is configured")
        if self.legacy is not None:
            LegacyBridge.validate_config(self)
        else:
            BaseAdapter.validate_config(self)

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        binding = CRM_BRIDGE_COMMANDS.get(command.command_type)
        if binding is not None:
            return await self._execute_crm(command, context, binding)
        if self.legacy is None:
            return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="unsupported_command_type")
        return await LegacyBridge.execute(self, command, context)

    async def _execute_crm(self, command: CommandEnvelope, context: AdapterContext, binding: tuple[str, str | None]) -> AdapterResult:
        if self.crm_bridge is None:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="crm_bridge_not_configured")
        configured = getattr(self.crm_bridge, "configured_tenant_id", None)
        if isinstance(configured, str) and configured and configured != command.tenant_id:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="crm_bridge_tenant_mismatch")
        method_name, key = binding
        payload = dict(command.payload)
        record = dict(payload.get("record") or {})
        args: list[Any] = []
        if key is not None:
            identifier = payload.get(key)
            if identifier is None:
                return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code=f"missing_{key}")
            args.append(identifier)
        args.append(record)  # complete_task takes the (empty) feedback record too
        from app.adapters.odoo.crm_bridge_client import CrmBridgeNotFound, CrmBridgeUnavailable

        try:
            response = await getattr(self.crm_bridge, method_name)(
                *args, correlation_id=command.correlation_id, idempotency_key=command.idempotency_key
            )
        except CrmBridgeNotFound:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="crm_record_not_found")
        except CrmBridgeUnavailable as exc:
            # The bridge raises this for transport errors and 5xx alike; a 5xx
            # after the request reached Odoo is ambiguous.
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return AdapterResult(Outcome.TRANSIENT, error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT, safe_error_code=type(exc).__name__)
        return self.normalize_result({"status_code": response.status_code, "body": response.body})

    def normalize_result(self, raw: Any) -> AdapterResult:
        if isinstance(raw, Mapping) and "status_code" in raw:
            status_code = int(raw["status_code"])
            raw_body = raw.get("body")
            body: Mapping[str, Any] = raw_body if isinstance(raw_body, Mapping) else {}
            reference = None
            for key in ("note_id", "task_id", "external_id", "ticket_id", "profile_id", "id"):
                if body.get(key) is not None:
                    reference = f"{key}:{body[key]}"
                    break
            if reference is not None and reference.split(":", 1)[0] in {"note_id", "task_id"} and body.get("profile_id") is not None:
                # The parent profile is the only read surface for notes/tasks;
                # persist it with the reference so a later readback (or a
                # reconciler in another process) does not depend on the payload.
                reference = f"{reference}{PARENT_REFERENCE_SEPARATOR}profile_id:{body['profile_id']}"
            outcome = classify_status(status_code)
            if outcome is Outcome.COMPLETED:
                outcome = Outcome.ACCEPTED  # completion is decided by readback
            return AdapterResult(
                outcome,
                provider_operation_id=reference,
                error_class=None if outcome is Outcome.ACCEPTED else ErrorClass.NON_RETRYABLE if outcome is Outcome.REJECTED else ErrorClass.AMBIGUOUS,
                safe_error_code=None if outcome is Outcome.ACCEPTED else f"odoo_http_{status_code}",
            )
        return LegacyBridge.normalize_result(self, raw)

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        if operation.command_type in CRM_BRIDGE_COMMANDS:
            return await self._readback_crm(operation, context)
        if self.legacy is None:
            return ReadbackResult(ReadbackStatus.UNSUPPORTED, safe_error_code="readback_unsupported")
        return await LegacyBridge.readback(self, operation, context)

    async def _readback_crm(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        if self.crm_bridge is None:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code="crm_bridge_not_configured")
        entity = operation.command_type.split(".")[1]
        reference = operation.provider_operation_id or ""
        if entity in CRM_LIST_READBACK:
            return await self._readback_crm_list(operation, context, reference)
        reader = CRM_READBACK.get(entity)
        if reader is None or ":" not in reference:
            return ReadbackResult(ReadbackStatus.UNSUPPORTED, safe_error_code="crm_readback_unsupported")
        method_name, key, cast = reader
        ref_key, _, ref_value = reference.partition(":")
        if ref_key != key:
            return ReadbackResult(ReadbackStatus.MISMATCH, safe_error_code="crm_reference_mismatch")
        from app.adapters.odoo.crm_bridge_client import CrmBridgeNotFound, CrmBridgeUnavailable

        try:
            response = await getattr(self.crm_bridge, method_name)(cast(ref_value), correlation_id=operation.correlation_id)
        except CrmBridgeNotFound:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="crm_record_not_found")
        except (CrmBridgeUnavailable, httpx.HTTPError) as exc:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        except (TypeError, ValueError):
            return ReadbackResult(ReadbackStatus.MISMATCH, safe_error_code="crm_reference_invalid")
        body = response.body if isinstance(response.body, Mapping) else {}
        observed = body.get(key)
        if response.status_code == 200 and observed is not None and str(observed) == ref_value:
            return ReadbackResult(ReadbackStatus.MATCHED, provider_operation_id=reference, evidence={key: str(observed)})
        return ReadbackResult(ReadbackStatus.MISMATCH, provider_operation_id=reference, evidence={"status_code": response.status_code})

    async def _readback_crm_list(self, operation: CommandOperation, context: AdapterContext, reference: str) -> ReadbackResult:
        """Notes and tasks: the parent profile's list is the read surface.

        The parent comes from the persisted reference (``note_id:N@profile_id:P``
        when the bridge returned it) or from the command payload's
        ``contact_id``; ``crm.task.update`` carries neither today, which is an
        explicit UNSUPPORTED (recorded, never a silent completion). A create or
        update matches when the record is listed and the fields the list
        exposes agree with the requested record; ``crm.task.complete`` matches
        when the activity is gone, since Odoo unlinks a completed activity.
        """
        entity = operation.command_type.split(".")[1]
        action = operation.command_type.split(".")[2]
        method_name, key, compared = CRM_LIST_READBACK[entity]
        own, _, parent = reference.partition(PARENT_REFERENCE_SEPARATOR)
        ref_key, _, ref_value = own.partition(":")
        if ref_key != key or not ref_value:
            return ReadbackResult(ReadbackStatus.MISMATCH, safe_error_code="crm_reference_mismatch")
        parent_value: Any = None
        if parent.startswith("profile_id:"):
            parent_value = parent.partition(":")[2]
        elif context.payload is not None:
            parent_value = context.payload.get("contact_id")
        try:
            profile_id = int(parent_value)
        except (TypeError, ValueError):
            return ReadbackResult(
                ReadbackStatus.UNSUPPORTED,
                provider_operation_id=reference,
                safe_error_code="crm_parent_profile_unknown",
                evidence={"reason": "the bridge lists notes/tasks by profile only and this command carries no profile"},
            )
        from app.adapters.odoo.crm_bridge_client import CrmBridgeNotFound, CrmBridgeUnavailable

        try:
            response = await getattr(self.crm_bridge, method_name)(profile_id, correlation_id=operation.correlation_id)
        except CrmBridgeNotFound:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="crm_parent_profile_not_found")
        except (CrmBridgeUnavailable, httpx.HTTPError) as exc:
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        body = response.body if isinstance(response.body, Mapping) else {}
        items = body.get("items") if response.status_code == 200 else None
        if not isinstance(items, list):
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, provider_operation_id=reference, safe_error_code=f"odoo_http_{response.status_code}")
        listed = next((item for item in items if isinstance(item, Mapping) and str(item.get(key)) == ref_value), None)
        evidence: dict[str, Any] = {key: ref_value, "profile_id": str(profile_id), "listed": listed is not None}
        if action == "complete":
            status = ReadbackStatus.MATCHED if listed is None else ReadbackStatus.MISMATCH
            return ReadbackResult(status, provider_operation_id=reference, evidence=evidence)
        if listed is None:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, provider_operation_id=reference, evidence=evidence)
        record = dict((context.payload or {}).get("record") or {})
        drift = sorted(field for field in compared if field in record and str(record[field]) != str(listed.get(field)))
        if drift:
            evidence["drift"] = drift
            return ReadbackResult(ReadbackStatus.MISMATCH, provider_operation_id=reference, evidence=evidence)
        return ReadbackResult(ReadbackStatus.MATCHED, provider_operation_id=reference, evidence=evidence)


# --- factories --------------------------------------------------------------------------


def _try(name: str, build: Callable[[], BaseAdapter]) -> BaseAdapter | None:
    try:
        adapter = build()
        adapter.validate_config()
        return adapter
    except Exception as exc:  # noqa: BLE001 - fail closed: an unconfigured provider is simply unavailable
        logger.info("provider adapter %s not registered: %s", name, type(exc).__name__)
        return None


def provider_adapters(settings: Settings, *, http: httpx.AsyncClient | None) -> tuple[BaseAdapter, ...]:
    """The real provider adapters, each registered only when it validates."""
    from app.calling_contract import HANGUP, ORIGINATE
    from app.klyrow_email_adapter import KlyrowEmailAdapter, KlyrowEmailAdapterError
    from app.odoo_provider_adapter import OdooProviderAdapter, OdooProviderAdapterError
    from app.postly_social_adapter import PostlySocialAdapter, PostlySocialAdapterError
    from app.telnexa_provider_adapter import TelnexaProviderAdapterError, TelnexaSmsAdapter
    from app.vicidial_internal_call_adapter import VicidialInternalCallAdapter, VicidialInternalCallPreDispatchRejected
    from app.platform.adapters.whatsapp import WhatsAppProviderAdapter

    def odoo() -> BaseAdapter:
        crm_bridge = None
        try:
            from app.adapters.odoo.crm_bridge_client import OdooCrmBridgeClient

            crm_bridge = OdooCrmBridgeClient(settings, client=http)
        except Exception:  # noqa: BLE001 - CrmBridgeNotConfigured or a settings gap: CRM surfaces stay unavailable
            crm_bridge = None
        legacy: OdooProviderAdapter | None = OdooProviderAdapter(settings)
        try:
            assert legacy is not None
            legacy._base_url()  # validates ODOO_INTEGRATION_BASE_URL without a request
            legacy._secret()
        except Exception:  # noqa: BLE001
            legacy = None
        return OdooAdapter(
            legacy=legacy,
            crm_bridge=crm_bridge,
            supported_command_types=frozenset({OdooProviderAdapter.UPSERT_LEAD}) | frozenset(CRM_BRIDGE_COMMANDS),
            transient_errors=(OdooProviderAdapterError,),
        )

    candidates: tuple[tuple[str, Callable[[], BaseAdapter]], ...] = (
        ("odoo-19", odoo),
        ("evolution-whatsapp", lambda: WhatsAppProviderAdapter(settings)),
        (
            "klyrow-email",
            lambda: LegacyBridge(
                adapter_id="klyrow-email",
                provider_family="email",
                connector_ids=("klyrow-email",),
                served_capabilities=("EMAIL_DELIVERY",),
                legacy=KlyrowEmailAdapter(settings),
                supported_command_types=frozenset({KlyrowEmailAdapter.COMMAND_TYPE}),
                transient_errors=(KlyrowEmailAdapterError,),
                required_settings=("KLYROW_EMAIL_API_BASE_URL", "KLYROW_EMAIL_MTLS_CA_FILE", "KLYROW_EMAIL_MTLS_CERT_FILE", "KLYROW_EMAIL_MTLS_KEY_FILE"),
            ),
        ),
        (
            "telnexa-sms",
            lambda: LegacyBridge(
                adapter_id="telnexa-sms",
                provider_family="sms",
                connector_ids=("telnexa-sms",),
                served_capabilities=("SMS_DELIVERY",),
                legacy=TelnexaSmsAdapter(settings),
                supported_command_types=frozenset({TelnexaSmsAdapter.SUBMIT_SMS}),
                transient_errors=(TelnexaProviderAdapterError,),
                required_settings=("TELNEXA_SMS_BASE_URL", "TELNEXA_SMS_API_KEY"),
            ),
        ),
        (
            "vicidial-restricted",
            lambda: LegacyBridge(
                adapter_id="vicidial-restricted",
                provider_family="telephony",
                connector_ids=("vicidial-restricted",),
                served_capabilities=("INTERNAL_TELEPHONY_CALLS", "PRODUCTION_DIALING"),
                legacy=VicidialInternalCallAdapter(settings, client=http),
                supported_command_types=frozenset({ORIGINATE, HANGUP}),
                rejected_errors=(VicidialInternalCallPreDispatchRejected,),
                required_settings=("VICIDIAL_INTERNAL_CALL_BASE_URL", "VICIDIAL_INTERNAL_CALL_SERVICE_IDENTITY", "VICIDIAL_INTERNAL_CALL_HMAC_FILE"),
            ),
        ),
        (
            "postly-social",
            lambda: LegacyBridge(
                adapter_id="postly-social",
                provider_family="social",
                connector_ids=("postly-social",),
                served_capabilities=("SOCIAL_PUBLISH",),
                legacy=PostlySocialAdapter(settings),
                supported_command_types=frozenset({PostlySocialAdapter.COMMAND_TYPE}),
                transient_errors=(PostlySocialAdapterError,),
                required_settings=("POSTLY_SOCIAL_BASE_URL", "POSTLY_SOCIAL_API_KEY"),
            ),
        ),
    )
    return tuple(adapter for name, build in candidates if (adapter := _try(name, build)) is not None)
