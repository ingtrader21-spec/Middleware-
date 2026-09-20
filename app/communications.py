from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Mapping, Protocol

import asyncpg

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    PrivateAttr,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from .db.connection import database_connection_authority
from .canonical_contracts import validate_specialized_contract
from .commands import CommandCapabilityDisabled, CommandEnvelope, CommandService
from .control_plane_auth import (
    ControlPlaneCaller,
    authorize_command,
    caller_for_authorization,
)
from .security import AuthorizationError, RequestValidationError, authorize_tenant
from .sms import compliance_keyword, normalize_e164, normalize_sms_sender, sms_segments


CommunicationChannel = Literal["email", "sms", "voice"]
SUPPORTED_MESSAGE_CHANNELS = frozenset({"email", "sms"})
EMAIL_ADDRESS = TypeAdapter(EmailStr)
CHANNEL_COMMAND = {
    "email": ("email.message.send.v1", "klyrow-email", "EMAIL_DELIVERY", "klyrow"),
    "sms": ("sms.message.submit.v1", "telnexa-sms", "SMS_DELIVERY", "telnexa"),
}
MessageStatus = Literal[
    "accepted",
    "queued",
    "dispatched",
    "delivered",
    "failed",
    "cancelled",
    "suppressed",
    "expired",
    "indeterminate",
]


class CommunicationsError(RuntimeError):
    status_code = 400
    code = "communications_invalid"
    retryable = False


class CommunicationsConflict(CommunicationsError):
    status_code = 409
    code = "communications_conflict"


class CommunicationsNotFound(CommunicationsError):
    status_code = 404
    code = "communications_not_found"


class MessageContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str | None = Field(default=None, max_length=998)
    text: str | None = Field(default=None, max_length=200_000)
    html: str | None = Field(default=None, max_length=200_000)
    templateId: uuid.UUID | None = None
    templateVersion: int | None = Field(default=None, ge=1)
    variables: dict[str, Any] | None = None
    mediaUrls: list[str] | None = Field(default=None, max_length=20)

    @model_validator(mode="after")
    def require_content(self) -> "MessageContent":
        if not any((self.text, self.html, self.templateId)):
            raise ValueError("message content requires text, html, or templateId")
        return self


class CreateMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: CommunicationChannel
    from_: str | None = Field(default=None, alias="from", min_length=1, max_length=300)
    to: list[str] = Field(min_length=1, max_length=1000)
    senderIdentityId: uuid.UUID | None = None
    domainId: uuid.UUID | None = None
    content: MessageContent
    scheduledAt: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scheduledAt")
    @classmethod
    def require_scheduled_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("scheduledAt must include timezone")
        return value

    @model_validator(mode="after")
    def validate_channel_contract(self) -> "CreateMessageRequest":
        if self.channel not in SUPPORTED_MESSAGE_CHANNELS:
            raise ValueError("implemented channels are email and sms")
        if self.from_ is None and self.senderIdentityId is None:
            raise ValueError("message requires from or senderIdentityId")
        if self.channel == "email":
            try:
                sender = (
                    str(EMAIL_ADDRESS.validate_python(self.from_)).lower()
                    if self.from_ is not None
                    else None
                )
                recipients = [
                    str(EMAIL_ADDRESS.validate_python(value)).lower()
                    for value in self.to
                ]
            except ValidationError as exc:
                raise ValueError("email sender and recipients must be valid addresses") from exc
            object.__setattr__(self, "from_", sender)
            object.__setattr__(self, "to", recipients)
            return self

        if len(self.to) != 1:
            raise ValueError("SMS submission requires exactly one recipient")
        if self.domainId is not None:
            raise ValueError("SMS does not accept domainId")
        if self.content.text is None:
            raise ValueError("SMS content.text is required")
        if any(
            (
                self.content.subject,
                self.content.html,
                self.content.templateId,
                self.content.templateVersion,
                self.content.variables,
                self.content.mediaUrls,
            )
        ):
            raise ValueError("SMS API currently accepts text content only")
        try:
            sender = normalize_sms_sender(self.from_) if self.from_ is not None else None
            recipients = [normalize_e164(self.to[0])]
            sms_segments(self.content.text)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        object.__setattr__(self, "from_", sender)
        object.__setattr__(self, "to", recipients)
        return self


class CommunicationMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The durable version belongs to this particular in-memory value, not to
    # the message key globally.  model_copy() carries private attributes, so a
    # mutation that started before a provider callback retains the version it
    # actually read and cannot overwrite the newer durable projection.
    _persisted_snapshot: tuple[datetime, str] | None = PrivateAttr(default=None)

    messageId: uuid.UUID
    tenantId: str
    channel: CommunicationChannel
    direction: Literal["outbound", "inbound"]
    status: MessageStatus
    correlationId: str
    idempotencyKey: str
    operationId: uuid.UUID | None = None
    provider: str | None = None
    providerReference: str | None = None
    failureCode: str | None = None
    failureMessage: str | None = None
    createdAt: datetime
    acceptedAt: datetime | None = None
    dispatchedAt: datetime | None = None
    completedAt: datetime | None = None
    updatedAt: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class MessageEvent(BaseModel):
    eventId: uuid.UUID
    messageId: uuid.UUID
    type: str
    status: MessageStatus
    occurredAt: datetime
    provider: str | None = None
    providerReference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Paged(BaseModel):
    items: list[Any]
    nextCursor: str | None = None


class CommunicationMessagePage(BaseModel):
    items: list[CommunicationMessage]
    nextCursor: str | None = None


class CommunicationEventPage(BaseModel):
    items: list[MessageEvent]
    nextCursor: str | None = None


class ProviderHealthReport(BaseModel):
    status: str
    checkedAt: datetime
    providers: list[dict[str, Any]]


class ProviderReputationReport(BaseModel):
    status: str
    checkedAt: datetime
    domains: list[dict[str, Any]]
    providers: list[dict[str, Any]]


class CommunicationUsageReport(BaseModel):
    from_: datetime = Field(alias="from")
    to: datetime
    totals: list[dict[str, Any]]


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _message_snapshot(message: CommunicationMessage) -> tuple[datetime, str]:
    return (
        message.updatedAt,
        _canonical_digest(message.model_dump(mode="json")),
    )


def _provider_status_to_canonical(status: str) -> MessageStatus:
    normalized = status.lower()
    if normalized in {"delivered", "delivrd"}:
        return "delivered"
    if normalized in {"queued", "created"}:
        return "queued"
    if normalized in {
        "processing",
        "submitted",
        "provider_accepted",
        "sent",
        "acceptd",
        "enroute",
    }:
        return "dispatched"
    if normalized in {"suppressed", "unsubscribed"}:
        return "suppressed"
    if normalized in {"cancelled", "canceled"}:
        return "cancelled"
    if normalized in {"expired"}:
        return "expired"
    if normalized in {"deferred", "unknown", "indeterminate"}:
        return "indeterminate"
    return "failed"


def _provider_event_uuid(tenant_id: str, event_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(event_id)
    except ValueError:
        return uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"codestra:communications:{tenant_id}:{event_id}",
        )


def _command_state_to_canonical(state: str) -> MessageStatus | None:
    if state in {"persisted", "queued"}:
        return "queued"
    if state in {"dispatching", "accepted", "readback_pending", "completed"}:
        return "dispatched"
    if state == "reconciliation_required":
        return "indeterminate"
    if state in {"failed", "dead_lettered"}:
        return "failed"
    if state == "cancelled":
        return "cancelled"
    return None


@dataclass
class MemoryCommunicationsStore:
    messages: dict[tuple[str, uuid.UUID], CommunicationMessage] = field(default_factory=dict)
    events: dict[tuple[str, uuid.UUID], list[MessageEvent]] = field(default_factory=dict)
    idempotency: dict[tuple[str, str, str], tuple[str, uuid.UUID]] = field(default_factory=dict)
    provider_event_digests: dict[tuple[str, str], str] = field(default_factory=dict)
    suppressions: set[tuple[str, str] | tuple[str, str, str]] = field(
        default_factory=set
    )
    denied_consent: set[tuple[str, str]] = field(default_factory=set)
    verified_senders: set[tuple[str, str]] = field(default_factory=set)
    verified_domains: set[tuple[str, str]] = field(default_factory=set)
    sender_identities: dict[tuple[str, uuid.UUID], str] = field(default_factory=dict)
    cancellations: set[tuple[str, uuid.UUID, str]] = field(default_factory=set)
    submission_locks: dict[tuple[str, str, str], asyncio.Lock] = field(
        default_factory=dict, repr=False
    )

    @asynccontextmanager
    async def submission_lock(
        self, tenant_id: str, route: str, idempotency_key: str
    ):
        key = (tenant_id, route, idempotency_key)
        lock = self.submission_locks.setdefault(key, asyncio.Lock())
        async with lock:
            yield

    async def refresh_idempotency(
        self, tenant_id: str, route: str, idempotency_key: str
    ) -> None:
        return None

    async def message_by_operation(
        self, tenant_id: str, operation_id: uuid.UUID
    ) -> CommunicationMessage | None:
        return next(
            (
                message
                for (tenant, _), message in self.messages.items()
                if tenant == tenant_id and message.operationId == operation_id
            ),
            None,
        )

    async def ready(self) -> bool:
        return True

    async def persist(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def synchronize_durable_message(self, message: CommunicationMessage) -> None:
        self.messages[(message.tenantId, message.messageId)] = message.model_copy(
            deep=True
        )

    async def message_by_idempotency(
        self, tenant_id: str, idempotency_key: str,
    ) -> CommunicationMessage:
        entry = self.idempotency.get(
            (tenant_id, "POST /v1/communications/messages", idempotency_key)
        )
        if entry is None:
            raise CommunicationsNotFound("message was not found")
        return self.messages[(tenant_id, entry[1])].model_copy(deep=True)

    def add_event(
        self,
        tenant_id: str,
        message_id: uuid.UUID,
        *,
        event_type: str,
        status: MessageStatus,
        provider: str | None = None,
        provider_reference: str | None = None,
        metadata: dict[str, Any] | None = None,
        event_id: uuid.UUID | None = None,
        occurred_at: datetime | None = None,
    ) -> MessageEvent:
        event = MessageEvent(
            eventId=event_id or uuid.uuid4(),
            messageId=message_id,
            type=event_type,
            status=status,
            occurredAt=occurred_at or datetime.now(UTC),
            provider=provider,
            providerReference=provider_reference,
            metadata=metadata or {},
        )
        key = (tenant_id, message_id)
        timeline = self.events.setdefault(key, [])
        if not any(item.eventId == event.eventId for item in timeline):
            timeline.append(event)
        return event


class PostgresCommunicationsStore(MemoryCommunicationsStore):
    """Durable communications projection; the command ledger remains authoritative."""

    def __init__(self, pool: asyncpg.Pool, *, owns_pool: bool = True) -> None:
        super().__init__()
        self.pool = pool
        # A pool shared through RuntimeContainer is closed by the container.
        self.owns_pool = owns_pool

    def synchronize_durable_message(self, message: CommunicationMessage) -> None:
        super().synchronize_durable_message(message)
        stored = self.messages[(message.tenantId, message.messageId)]
        stored._persisted_snapshot = _message_snapshot(stored)

    @asynccontextmanager
    async def submission_lock(
        self, tenant_id: str, route: str, idempotency_key: str
    ):
        identity = f"{tenant_id}\0{route}\0{idempotency_key}"
        async with self.pool.acquire() as conn:
            await conn.execute("SELECT pg_advisory_lock(hashtextextended($1,0))", identity)
            try:
                yield
            finally:
                await conn.execute(
                    "SELECT pg_advisory_unlock(hashtextextended($1,0))", identity
                )

    async def refresh_idempotency(
        self, tenant_id: str, route: str, idempotency_key: str
    ) -> None:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT i.request_sha256,i.message_id,m.payload "
                "FROM middleware_communication_idempotency i "
                "JOIN middleware_communication_messages m "
                "ON m.tenant_id=i.tenant_id AND m.message_id=i.message_id "
                "WHERE i.tenant_id=$1 AND i.route=$2 AND i.idempotency_key=$3",
                tenant_id,
                route,
                idempotency_key,
            )
        if row is None:
            return
        message = (
            CommunicationMessage.model_validate_json(row["payload"])
            if isinstance(row["payload"], str)
            else CommunicationMessage.model_validate(row["payload"])
        )
        self.synchronize_durable_message(message)
        self.idempotency[(tenant_id, route, idempotency_key)] = (
            row["request_sha256"],
            row["message_id"],
        )

    async def message_by_operation(
        self, tenant_id: str, operation_id: uuid.UUID
    ) -> CommunicationMessage | None:
        existing = await super().message_by_operation(tenant_id, operation_id)
        if existing is not None:
            return existing
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT payload FROM middleware_communication_messages "
                "WHERE tenant_id=$1 AND payload->>'operationId'=$2 LIMIT 1",
                tenant_id,
                str(operation_id),
            )
        if row is None:
            return None
        message = (
            CommunicationMessage.model_validate_json(row["payload"])
            if isinstance(row["payload"], str)
            else CommunicationMessage.model_validate(row["payload"])
        )
        self.synchronize_durable_message(message)
        return message

    async def message_by_idempotency(
        self, tenant_id: str, idempotency_key: str,
    ) -> CommunicationMessage:
        # Read the durable projection for every reconciliation. A different API
        # process or event worker may have accepted or updated this message.
        async with self.pool.acquire() as conn:
            raw = await conn.fetchval(
                "SELECT m.payload FROM middleware_communication_idempotency i "
                "JOIN middleware_communication_messages m "
                "ON m.tenant_id=i.tenant_id AND m.message_id=i.message_id "
                "WHERE i.tenant_id=$1 AND i.route=$2 AND i.idempotency_key=$3",
                tenant_id, "POST /v1/communications/messages", idempotency_key,
            )
        if raw is None:
            raise CommunicationsNotFound("message was not found")
        return (
            CommunicationMessage.model_validate_json(raw)
            if isinstance(raw, str) else CommunicationMessage.model_validate(raw)
        )

    @classmethod
    async def connect(cls, database_url: str) -> "PostgresCommunicationsStore":
        authority = database_connection_authority(
            database_url,
            application_name="middleware-communications-store",
        )
        pool = await asyncpg.create_pool(
            **authority.asyncpg_pool_kwargs(min_size=1, max_size=5)
        )
        store = cls(pool)
        await store._load()
        return store

    async def _load(self) -> None:
        async with self.pool.acquire() as conn:
            for row in await conn.fetch("SELECT payload FROM middleware_communication_messages"):
                raw = row["payload"]
                message = (CommunicationMessage.model_validate_json(raw) if isinstance(raw, str) else CommunicationMessage.model_validate(raw))
                self.synchronize_durable_message(message)
            for row in await conn.fetch("SELECT tenant_id,payload FROM middleware_communication_events ORDER BY occurred_at,id"):
                raw = row["payload"]
                event = (MessageEvent.model_validate_json(raw) if isinstance(raw, str) else MessageEvent.model_validate(raw))
                self.events.setdefault((row["tenant_id"], event.messageId), []).append(event)
            for row in await conn.fetch("SELECT tenant_id,route,idempotency_key,request_sha256,message_id FROM middleware_communication_idempotency"):
                self.idempotency[(row["tenant_id"], row["route"], row["idempotency_key"])] = (row["request_sha256"], row["message_id"])
            for row in await conn.fetch("SELECT tenant_id,provider_event_id,request_sha256 FROM middleware_communication_provider_events"):
                self.provider_event_digests[(row["tenant_id"], row["provider_event_id"])] = row["request_sha256"]
            for row in await conn.fetch("SELECT tenant_id,channel,subject FROM middleware_communication_suppressions"):
                self.suppressions.add((row["tenant_id"], row["channel"], row["subject"]))
            for row in await conn.fetch("SELECT tenant_id,message_id,idempotency_key FROM middleware_communication_cancellations"):
                self.cancellations.add((row["tenant_id"], row["message_id"], row["idempotency_key"]))

    async def persist(self) -> None:
        persisted_messages: list[tuple[CommunicationMessage, tuple[datetime, str]]] = []
        async with self.pool.acquire() as conn, conn.transaction():
            for (tenant, message_id), message in self.messages.items():
                snapshot = _message_snapshot(message)
                previous = message._persisted_snapshot
                if previous == snapshot:
                    continue
                if previous is None:
                    written_at = await conn.fetchval(
                        "INSERT INTO middleware_communication_messages"
                        "(tenant_id,message_id,payload,updated_at) "
                        "VALUES($1,$2,$3::jsonb,$4) "
                        "ON CONFLICT(tenant_id,message_id) DO NOTHING "
                        "RETURNING updated_at",
                        tenant,
                        message_id,
                        message.model_dump_json(),
                        message.updatedAt,
                    )
                else:
                    written_at = await conn.fetchval(
                        "UPDATE middleware_communication_messages "
                        "SET payload=$3::jsonb,updated_at=$4 "
                        "WHERE tenant_id=$1 AND message_id=$2 AND updated_at=$5 "
                        "RETURNING updated_at",
                        tenant,
                        message_id,
                        message.model_dump_json(),
                        message.updatedAt,
                        previous[0],
                    )
                if written_at is None:
                    current = await conn.fetchval(
                        "SELECT payload FROM middleware_communication_messages "
                        "WHERE tenant_id=$1 AND message_id=$2",
                        tenant,
                        message_id,
                    )
                    if current is not None:
                        durable = (
                            CommunicationMessage.model_validate_json(current)
                            if isinstance(current, str)
                            else CommunicationMessage.model_validate(current)
                        )
                        self.synchronize_durable_message(durable)
                    raise CommunicationsConflict(
                        "communication message changed in another worker"
                    )
                persisted_messages.append((message, snapshot))
            for (tenant, _), timeline in self.events.items():
                for event in timeline:
                    await conn.execute("INSERT INTO middleware_communication_events(tenant_id,event_id,message_id,occurred_at,payload) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(tenant_id,event_id) DO NOTHING", tenant, event.eventId, event.messageId, event.occurredAt, event.model_dump_json())
            for (tenant, route, key), (digest, message_id) in self.idempotency.items():
                await conn.execute("INSERT INTO middleware_communication_idempotency(tenant_id,route,idempotency_key,request_sha256,message_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", tenant, route, key, digest, message_id)
            for (tenant, event_id), digest in self.provider_event_digests.items():
                await conn.execute("INSERT INTO middleware_communication_provider_events(tenant_id,provider_event_id,request_sha256) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", tenant, event_id, digest)
            for item in self.suppressions:
                if len(item) == 3:
                    await conn.execute("INSERT INTO middleware_communication_suppressions(tenant_id,channel,subject) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", *item)
            for tenant, message_id, key in self.cancellations:
                await conn.execute("INSERT INTO middleware_communication_cancellations(tenant_id,message_id,idempotency_key) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", tenant, message_id, key)
        for message, snapshot in persisted_messages:
            message._persisted_snapshot = snapshot

    async def ready(self) -> bool:
        return await self.pool.fetchval("SELECT to_regclass('middleware_communication_messages') IS NOT NULL") is True

    async def close(self) -> None:
        if self.owns_pool:
            await self.pool.close()


class CommunicationsProviderReadAdapter(Protocol):
    async def health(self, tenant_id: str) -> dict[str, Any]:
        ...

    async def reputation(self, tenant_id: str) -> dict[str, Any]:
        ...


class DisabledCommunicationsProviderReadAdapter:
    async def health(self, tenant_id: str) -> dict[str, Any]:
        return {
            "status": "disabled",
            "checkedAt": datetime.now(UTC).isoformat(),
            "providers": [
                {
                    "provider": "klyrow",
                    "channel": "email",
                    "status": "disabled",
                    "reason": "EMAIL_DELIVERY_ENABLED is false",
                },
                {
                    "provider": "telnexa",
                    "channel": "sms",
                    "status": "disabled",
                    "reason": "SMS_DELIVERY_ENABLED is false",
                },
            ],
        }

    async def reputation(self, tenant_id: str) -> dict[str, Any]:
        return {
            "status": "watch",
            "checkedAt": datetime.now(UTC).isoformat(),
            "domains": [],
            "providers": [
                {
                    "provider": "klyrow",
                    "channel": "email",
                    "status": "watch",
                    "queueDepth": 0,
                },
                {
                    "provider": "telnexa",
                    "channel": "sms",
                    "status": "watch",
                    "queueDepth": 0,
                },
            ],
        }


@dataclass
class CommunicationsService:
    store: MemoryCommunicationsStore | PostgresCommunicationsStore
    commands: CommandService
    umbrella_controls: Mapping[str, bool] = field(default_factory=dict)
    adapter: CommunicationsProviderReadAdapter = field(
        default_factory=DisabledCommunicationsProviderReadAdapter
    )

    async def submit_message(
        self,
        request: CreateMessageRequest,
        *,
        tenant_id: str,
        correlation_id: str,
        idempotency_key: str,
        actor: str,
        authorization: str,
        token_verifier: Any,
        _governed_metadata: Mapping[str, Any] | None = None,
    ) -> tuple[CommunicationMessage, bool]:
        route = "POST /v1/communications/messages"
        async with self.store.submission_lock(tenant_id, route, idempotency_key):
            await self.store.refresh_idempotency(tenant_id, route, idempotency_key)
            return await self._submit_message_unlocked(
                request,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
                actor=actor,
                authorization=authorization,
                token_verifier=token_verifier,
                _governed_metadata=_governed_metadata,
            )

    async def _submit_message_unlocked(
        self,
        request: CreateMessageRequest,
        *,
        tenant_id: str,
        correlation_id: str,
        idempotency_key: str,
        actor: str,
        authorization: str,
        token_verifier: Any,
        _governed_metadata: Mapping[str, Any] | None = None,
    ) -> tuple[CommunicationMessage, bool]:
        command_type, target, capability, provider = CHANNEL_COMMAND[request.channel]
        caller = caller_for_authorization(authorization)
        claims = await token_verifier.verify(
            authorization,
            expected_client_id=caller.client_id,
            required_scope=caller.command_scope,
        )
        authorize_command(caller, command_type=command_type, target=target)
        authorize_tenant(claims, tenant_id)
        subject = claims.get("sub")
        if subject != actor:
            raise AuthorizationError("requested actor must equal token subject")
        if (
            caller.client_id == "n8n-automation"
            and self.umbrella_controls.get("N8N_EXTERNAL_PROVIDER_WRITES") is not True
        ):
            raise CommandCapabilityDisabled(
                "N8N_EXTERNAL_PROVIDER_WRITES is disabled"
            )
        body = request.model_dump(mode="json", by_alias=True)
        digest = _canonical_digest(body)
        key = (tenant_id, "POST /v1/communications/messages", idempotency_key)
        existing = self.store.idempotency.get(key)
        if existing is not None:
            existing_digest, existing_message_id = existing
            if existing_digest != digest:
                raise CommunicationsConflict("Idempotency-Key was reused with different content")
            return self.store.messages[(tenant_id, existing_message_id)].model_copy(), True

        if request.from_ is not None:
            sender = request.from_
        elif request.senderIdentityId is not None:
            try:
                sender = self.store.sender_identities[
                    (tenant_id, request.senderIdentityId)
                ]
            except KeyError as exc:
                raise RequestValidationError(
                    "sender identity is not active for tenant"
                ) from exc
        else:
            raise RequestValidationError("sender identity is required")
        if request.channel == "email":
            try:
                sender = str(EMAIL_ADDRESS.validate_python(sender)).lower()
            except ValidationError as exc:
                raise RequestValidationError("sender identity is not a valid email") from exc
        else:
            try:
                sender = normalize_sms_sender(sender)
            except ValueError as exc:
                raise RequestValidationError(str(exc)) from exc
        if (tenant_id, sender) not in self.store.verified_senders:
            raise RequestValidationError("sender identity is not verified for tenant")

        recipients = list(request.to)
        recipient = recipients[0]
        sender_domain = sender.rsplit("@", 1)[1] if "@" in sender else ""
        if (
            request.channel == "email"
            and (tenant_id, sender_domain) not in self.store.verified_domains
        ):
            raise RequestValidationError("sender domain is not verified for tenant")

        category = str(request.metadata.get("category") or "transactional").lower()
        if request.channel == "sms" and category not in {
            "transactional",
            "service",
            "marketing",
        }:
            raise RequestValidationError("SMS category is not supported")
        status: MessageStatus = "accepted"
        failure_code: str | None = None
        failure_message: str | None = None
        if (
            (tenant_id, recipient) in self.store.suppressions
            or (tenant_id, request.channel, recipient) in self.store.suppressions
        ):
            status = "suppressed"
            failure_code = "recipient_suppressed"
            failure_message = "recipient is suppressed before provider submission"
        elif (
            (tenant_id, recipient) in self.store.denied_consent
            or request.metadata.get("consent") == "denied"
            or (
                category == "marketing"
                and request.metadata.get("consent") != "granted"
            )
        ):
            status = "suppressed"
            failure_code = "consent_required"
            failure_message = "recipient does not have required consent"

        now = datetime.now(UTC)
        message_id = uuid.uuid4()
        command_id = uuid.uuid4()
        effective_metadata = {
            **request.metadata,
            **(_governed_metadata or {}),
        }
        message_metadata = {
            **effective_metadata,
            "recipientCount": len(recipients),
        }
        command_payload: dict[str, Any]
        if request.channel == "sms":
            assert request.content.text is not None
            segment_info = sms_segments(request.content.text)
            message_metadata.update(
                {
                    "encoding": segment_info.encoding,
                    "characters": segment_info.characters,
                    "segments": segment_info.segments,
                }
            )
            command_payload = {
                "message_id": str(message_id),
                "channel": "sms",
                "destination": recipient,
                "sender": sender,
                "content": request.content.text,
                "encoding": segment_info.encoding,
                "characters": segment_info.characters,
                "segments": segment_info.segments,
                "category": category,
                "client_reference": str(message_id),
                "scheduled_at": (
                    request.scheduledAt.isoformat() if request.scheduledAt else None
                ),
                "billing_account_id": request.metadata.get("billingAccountId"),
                "campaign_id": request.metadata.get("campaignId"),
            }
        else:
            command_payload = {
                "message_id": str(message_id),
                "channel": "email",
                "from": sender,
                "to": recipients,
                "content": request.content.model_dump(
                    mode="json",
                    exclude_none=True,
                ),
                "scheduled_at": (
                    request.scheduledAt.isoformat() if request.scheduledAt else None
                ),
                "metadata": effective_metadata,
            }
        message = CommunicationMessage(
            messageId=message_id,
            tenantId=tenant_id,
            channel=request.channel,
            direction="outbound",
            status=status,
            correlationId=correlation_id,
            idempotencyKey=idempotency_key,
            operationId=command_id if status != "suppressed" else None,
            provider=provider,
            failureCode=failure_code,
            failureMessage=failure_message,
            createdAt=now,
            acceptedAt=now,
            completedAt=now if status == "suppressed" else None,
            updatedAt=now,
            metadata=message_metadata,
        )
        command: CommandEnvelope | None = None
        if status != "suppressed":
            command = CommandEnvelope(
                command_id=command_id,
                command_type=command_type,
                command_version="1.0",
                target=target,
                tenant_id=tenant_id,
                requested_by=actor,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
                capability=capability,
                payload=command_payload,
            )
            if request.channel == "sms":
                validate_specialized_contract(
                    "telnexa_sms_command",
                    command.model_dump(mode="json"),
                )
            self.commands.policies.authorize(command)

        self.store.messages[(tenant_id, message_id)] = message
        self.store.idempotency[key] = (digest, message_id)
        self.store.add_event(
            tenant_id,
            message_id,
            event_type="accepted",
            status="accepted",
            provider=provider,
        )
        if status == "suppressed":
            self.store.add_event(
                tenant_id,
                message_id,
                event_type=failure_code or "suppressed",
                status="suppressed",
                provider=provider,
            )
            await self.store.persist()
            return message, False

        assert command is not None
        await self.commands.submit(
            command,
            authenticated_subject=actor,
            authenticated_client_id=caller.client_id,
        )
        message.status = "queued"
        message.updatedAt = datetime.now(UTC)
        self.store.messages[(tenant_id, message_id)] = message
        self.store.add_event(
            tenant_id,
            message_id,
            event_type="queued",
            status="queued",
            provider=provider,
        )
        await self.store.persist()
        return message, False

    def list_messages(self, tenant_id: str, *, channel: str | None = None, status: str | None = None) -> list[CommunicationMessage]:
        values = [item for (tenant, _), item in self.store.messages.items() if tenant == tenant_id]
        if channel:
            values = [item for item in values if item.channel == channel]
        if status:
            values = [item for item in values if item.status == status]
        return sorted(values, key=lambda item: item.createdAt, reverse=True)

    def get_message(self, tenant_id: str, message_id: uuid.UUID) -> CommunicationMessage:
        try:
            return self.store.messages[(tenant_id, message_id)]
        except KeyError as exc:
            raise CommunicationsNotFound("message was not found") from exc

    def get_cancellable_message_for_caller(
        self,
        tenant_id: str,
        message_id: uuid.UUID,
        *,
        caller: ControlPlaneCaller,
    ) -> CommunicationMessage:
        message = self.get_message(tenant_id, message_id)
        command_type, target, _, _ = CHANNEL_COMMAND[message.channel]
        cancel_command_type = command_type.rsplit(".", 2)[0] + ".cancel.v1"
        try:
            authorize_command(
                caller,
                command_type=cancel_command_type,
                target=target,
            )
        except AuthorizationError:
            # A caller without authority for this channel must observe the same
            # result as it would for an unknown message identifier.
            raise CommunicationsNotFound("message was not found") from None
        return message

    def message_events(self, tenant_id: str, message_id: uuid.UUID) -> list[MessageEvent]:
        self.get_message(tenant_id, message_id)
        return sorted(self.store.events.get((tenant_id, message_id), []), key=lambda item: item.occurredAt)

    async def refresh_command_status(
        self,
        tenant_id: str,
        message_id: uuid.UUID,
    ) -> CommunicationMessage:
        message = self.get_message(tenant_id, message_id)
        if message.operationId is None:
            return message
        operation = await self.commands.get(tenant_id, message.operationId)
        target_status = _command_state_to_canonical(operation.state)
        if target_status is None or target_status == message.status:
            return message
        if message.status in {"delivered", "failed", "cancelled", "suppressed", "expired"}:
            return message

        now = datetime.now(UTC)
        update: dict[str, Any] = {
            "status": target_status,
            "providerReference": (
                operation.provider_operation_id or message.providerReference
            ),
            "updatedAt": now,
        }
        if target_status == "indeterminate":
            update.update(
                {
                    "failureCode": "provider_outcome_unknown",
                    "failureMessage": (
                        operation.last_error
                        or "provider outcome requires authoritative read-back"
                    ),
                }
            )
        elif target_status == "failed":
            update.update(
                {
                    "failureCode": "provider_command_failed",
                    "failureMessage": operation.last_error,
                    "completedAt": now,
                }
            )
        updated = message.model_copy(update=update)
        self.store.messages[(tenant_id, message_id)] = updated
        self.store.add_event(
            tenant_id,
            message_id,
            event_type=f"command.{operation.state}",
            status=target_status,
            provider=message.provider,
            provider_reference=updated.providerReference,
            metadata={"commandState": operation.state},
            event_id=uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"codestra:communications:{tenant_id}:{operation.command_id}:{operation.state}",
            ),
        )
        await self.store.persist()
        return updated

    async def cancel(
        self,
        tenant_id: str,
        message_id: uuid.UUID,
        *,
        idempotency_key: str,
        actor: str,
        authorization: str,
        token_verifier: Any,
    ) -> tuple[CommunicationMessage, bool]:
        caller = caller_for_authorization(authorization)
        claims = await token_verifier.verify(
            authorization,
            expected_client_id=caller.client_id,
            required_scope=caller.command_scope,
        )
        authorize_tenant(claims, tenant_id)
        if claims.get("sub") != actor:
            raise AuthorizationError("requested actor must equal token subject")
        message = self.get_cancellable_message_for_caller(
            tenant_id,
            message_id,
            caller=caller,
        )
        replay_key = (tenant_id, message_id, idempotency_key)
        if replay_key in self.store.cancellations:
            return message.model_copy(), True
        if message.status not in {"accepted", "queued"}:
            raise CommunicationsConflict("message cannot be cancelled in its current state")
        if message.operationId is None:
            raise CommunicationsConflict("message does not own a cancellable command")
        operation = await self.commands.get(tenant_id, message.operationId)
        if operation.state not in {"persisted", "queued"}:
            raise CommunicationsConflict("message command is already being dispatched")
        cancelled_operation = await self.commands.mutate_operation(
            tenant_id,
            message.operationId,
            action="cancel",
            actor_id=actor,
            idempotency_key=idempotency_key,
            expected_version=operation.resource_version,
            reason="communication cancelled before provider dispatch",
        )
        if cancelled_operation.state != "cancelled":
            raise CommunicationsConflict("message command cancellation requires reconciliation")
        updated = message.model_copy(
            update={
                "status": "cancelled",
                "completedAt": datetime.now(UTC),
                "updatedAt": datetime.now(UTC),
            }
        )
        self.store.messages[(tenant_id, message_id)] = updated
        self.store.cancellations.add(replay_key)
        self.store.add_event(
            tenant_id,
            message_id,
            event_type="cancelled",
            status="cancelled",
            provider=message.provider,
        )
        await self.store.persist()
        return updated, False

    def _record_inbound_sms(self, envelope: Any, payload: dict[str, Any]) -> bool:
        tenant_id = envelope.tenant_id
        event_id = str(envelope.event_id)
        sender_value = (
            payload.get("from")
            or payload.get("sender")
            or payload.get("from_number")
        )
        destination_value = (
            payload.get("to")
            or payload.get("destination")
            or payload.get("to_number")
        )
        if not isinstance(sender_value, str) or not isinstance(destination_value, str):
            raise RequestValidationError(
                "SMS inbound event requires sender and destination"
            )
        try:
            sender = normalize_e164(sender_value)
            destination = normalize_e164(destination_value)
        except ValueError as exc:
            raise RequestValidationError(str(exc)) from exc
        content = str(
            payload.get("content")
            or payload.get("text")
            or payload.get("body_preview")
            or ""
        )
        action = compliance_keyword(content)
        if envelope.event_type == "codestra.sms.recipient.opted_out":
            action = "stop"
        elif envelope.event_type == "codestra.sms.help_requested":
            action = "help"
        provider_reference = (
            payload.get("inboundMessageId")
            or payload.get("inbound_message_id")
            or payload.get("telnexa_message_id")
            or payload.get("provider_message_id")
            or event_id
        )
        message_id = _provider_event_uuid(tenant_id, event_id)
        now = datetime.now(UTC)
        metadata: dict[str, Any] = {
            "sender": sender,
            "destination": destination,
            "bodyPreview": content[:120],
            "complianceAction": action,
        }
        if content:
            segment_info = sms_segments(content)
            metadata.update(
                {
                    "encoding": segment_info.encoding,
                    "characters": segment_info.characters,
                    "segments": segment_info.segments,
                }
            )
        message = CommunicationMessage(
            messageId=message_id,
            tenantId=tenant_id,
            channel="sms",
            direction="inbound",
            status="delivered",
            correlationId=envelope.correlation_id,
            idempotencyKey=envelope.idempotency_key,
            provider="telnexa",
            providerReference=str(provider_reference),
            createdAt=envelope.occurred_at,
            acceptedAt=now,
            completedAt=now,
            updatedAt=now,
            metadata=metadata,
        )
        self.store.messages[(tenant_id, message_id)] = message
        self.store.add_event(
            tenant_id,
            message_id,
            event_type=envelope.event_type,
            status="delivered",
            provider="telnexa",
            provider_reference=message.providerReference,
            metadata={"complianceAction": action},
            event_id=_provider_event_uuid(tenant_id, event_id),
            occurred_at=envelope.occurred_at,
        )
        if action == "stop":
            self.store.suppressions.add((tenant_id, "sms", sender))
            self.store.add_event(
                tenant_id,
                message_id,
                event_type="codestra.sms.recipient.opted_out",
                status="suppressed",
                provider="telnexa",
                provider_reference=message.providerReference,
                metadata={"subject": sender, "source": "inbound_sms"},
                event_id=uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"codestra:communications:{tenant_id}:{event_id}:stop",
                ),
                occurred_at=envelope.occurred_at,
            )
        elif action == "help":
            self.store.add_event(
                tenant_id,
                message_id,
                event_type="codestra.sms.help_requested",
                status="delivered",
                provider="telnexa",
                provider_reference=message.providerReference,
                metadata={"subject": sender},
                event_id=uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"codestra:communications:{tenant_id}:{event_id}:help",
                ),
                occurred_at=envelope.occurred_at,
            )
        return True

    async def record_provider_event(self, envelope: Any) -> bool:
        payload = envelope.payload if hasattr(envelope, "payload") else {}
        tenant_id = envelope.tenant_id
        event_id = str(envelope.event_id)
        event_digest = _canonical_digest(envelope.model_dump(mode="json"))
        replay_key = (tenant_id, event_id)
        existing_digest = self.store.provider_event_digests.get(replay_key)
        if existing_digest is not None:
            if existing_digest != event_digest:
                raise CommunicationsConflict(
                    "provider event identity was reused with different content"
                )
            return False

        if envelope.event_type in {
            "codestra.events.sms_received",
            "codestra.sms.inbound.received",
            "codestra.sms.help_requested",
            "codestra.sms.recipient.opted_out",
        }:
            recorded = self._record_inbound_sms(envelope, payload)
            self.store.provider_event_digests[replay_key] = event_digest
            await self.store.persist()
            return recorded

        raw_message_id = (
            payload.get("messageId")
            or payload.get("message_id")
            or payload.get("middleware_message_id")
        )
        if not raw_message_id:
            return False
        try:
            message_id = uuid.UUID(str(raw_message_id))
        except ValueError:
            message_id = None
        message = (
            self.store.messages.get((tenant_id, message_id))
            if message_id is not None
            else None
        )
        if message is None:
            raw_operation_id = (
                payload.get("operationId")
                or payload.get("operation_id")
                or payload.get("command_id")
            )
            try:
                operation_id = uuid.UUID(str(raw_operation_id))
            except ValueError:
                operation_id = None
            if operation_id is not None:
                message = await self.store.message_by_operation(
                    tenant_id, operation_id
                )
        if message is None:
            return False
        message_id = message.messageId
        event_channel = (
            "sms"
            if envelope.source == "telnexa-gateway"
            or ".sms." in envelope.event_type
            else "email"
        )
        if message.channel != event_channel:
            raise CommunicationsConflict(
                "provider event channel does not match communication message"
            )
        raw_status = str(
            payload.get("status")
            or payload.get("canonical_status")
            or payload.get("provider_status")
            or envelope.event_type.rsplit(".", 1)[-1]
        )
        status = _provider_status_to_canonical(raw_status)
        is_email_unsubscribe = envelope.event_type in {
            "codestra.email.message.unsubscribed",
            "klyrow.email.unsubscribed",
        }
        if is_email_unsubscribe:
            raw_recipient = (
                payload.get("recipient")
                or payload.get("recipient_email")
                or payload.get("destination")
                or payload.get("email")
            )
            try:
                recipient = str(EMAIL_ADDRESS.validate_python(raw_recipient)).lower()
            except ValidationError as exc:
                raise RequestValidationError(
                    "email unsubscribe event requires a valid recipient"
                ) from exc
            self.store.suppressions.add((tenant_id, "email", recipient))
        provider_reference = (
            payload.get("providerReference")
            or payload.get("provider_reference")
            or payload.get("provider_message_id")
        )
        ignored_transition = (
            message.status == "delivered"
            and status != "delivered"
            and not is_email_unsubscribe
        )
        effective_status = message.status if ignored_transition else status
        now = datetime.now(UTC)
        updated = message.model_copy(
            update={
                "status": effective_status,
                "providerReference": (
                    str(provider_reference)
                    if provider_reference
                    else message.providerReference
                ),
                "failureCode": (
                    payload.get("failureCode")
                    or payload.get("failure_code")
                    or message.failureCode
                ),
                "failureMessage": (
                    payload.get("failureMessage")
                    or payload.get("failure_message")
                    or message.failureMessage
                ),
                "dispatchedAt": (
                    now if effective_status == "dispatched" else message.dispatchedAt
                ),
                "completedAt": (
                    now
                    if effective_status
                    in {"delivered", "failed", "cancelled", "suppressed", "expired"}
                    else message.completedAt
                ),
                "updatedAt": now,
            }
        )
        self.store.messages[(tenant_id, message_id)] = updated
        self.store.add_event(
            tenant_id,
            message_id,
            event_type=envelope.event_type,
            status=effective_status,
            provider=message.provider,
            provider_reference=updated.providerReference,
            metadata={
                "providerEventType": payload.get("providerEventType")
                or payload.get("provider_event_type"),
                "providerStatus": raw_status,
                "providerOccurredAt": envelope.occurred_at.isoformat(),
                "ignoredTransition": ignored_transition,
                "suppressionApplied": is_email_unsubscribe,
            },
            event_id=_provider_event_uuid(tenant_id, event_id),
        )
        self.store.provider_event_digests[replay_key] = event_digest
        await self.store.persist()
        return True
