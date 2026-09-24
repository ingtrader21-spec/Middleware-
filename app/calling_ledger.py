"""Calling facade over the existing command ledger and Temporal outbox.

There is no independent production queue or in-memory production call state.
The PostgreSQL reservation, audit and outbox commit in the same transaction.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any
from uuid import UUID

from .calling_contract import (
    CAPABILITY, CLIENT_ID, HANGUP, ORIGINATE, TARGET, TERMINAL_CALL_STATES,
    CallPrincipal, CallingGrant, OriginateRequest, operation_identity,
)
from .commands import (
    AUTHENTICATED_CLIENT_ID_KEY, CommandConflict, CommandEnvelope, CommandNotFound,
    CommandOperation, CommandPolicyRegistry, CommandService, MemoryCommandStore,
    PostgresCommandStore, authenticated_command_digest, verify_readback_evidence_digest,
)


def _decode_document(row: Any) -> CommandEnvelope:
    raw = row["payload"]
    document = json.loads(raw) if isinstance(raw, str) else dict(raw)
    client = document.pop(AUTHENTICATED_CLIENT_ID_KEY, None)
    envelope = CommandEnvelope.model_validate(document)
    if client != CLIENT_ID or authenticated_command_digest(envelope, client) != row["payload_sha256"]:
        raise CommandConflict("calling command provenance is invalid")
    return envelope


def _terminal(operation: CommandOperation, *, evidence_operation_id: str | None = None) -> bool:
    if operation.state == "cancelled":
        return True  # Existing cancellation logic permits this only before dispatch.
    evidence = operation.readback_evidence or {}
    return (
        operation.state == "completed"
        and operation.readback_evidence_sha256 is not None
        and evidence.get("call_state") in TERMINAL_CALL_STATES
        and evidence.get("operation_id") == (evidence_operation_id or str(operation.command_id))
        and evidence.get("tenant_id") == operation.tenant_id
        and evidence.get("internal_only") is True
        and evidence.get("external_dialing") is False
    )


class CallingLedger:
    def __init__(self, commands: CommandService) -> None:
        self.commands = commands
        self.store = commands.store
        # Only the explicit development/test MemoryCommandStore uses this cache.
        self._documents: dict[tuple[str, UUID], CommandEnvelope] = {}
        self._lock = asyncio.Lock()

    def _validate(self, command: CommandEnvelope) -> None:
        # Activate ONLY this narrow namespace after the API's protected grant or
        # same-call hangup authorization. Generic endpoints retain disabled caps.
        policies = self.commands.policies
        scoped = CommandService(self.store, CommandPolicyRegistry(
            policies.policies, {**policies.capabilities, CAPABILITY: True},
        ))
        scoped.validate_submission(command, authenticated_subject=command.requested_by,
                                   authenticated_client_id=CLIENT_ID)

    @staticmethod
    def _owner(document: CommandEnvelope, principal: CallPrincipal) -> None:
        if (document.target != TARGET or document.command_type != ORIGINATE
                or document.tenant_id != principal.tenant_id
                or document.requested_by != principal.subject
                or document.payload.get("actor") != principal.model_dump(mode="json")):
            # Do not disclose another agent's operation, even in the same tenant.
            raise CommandNotFound("calling request was not found")

    async def get(self, principal: CallPrincipal, operation_id: UUID) -> tuple[CommandEnvelope, CommandOperation]:
        document: CommandEnvelope | None
        original: CommandEnvelope | None
        if isinstance(self.store, PostgresCommandStore):
            async with self.store.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT payload,payload_sha256 FROM middleware_commands "
                    "WHERE tenant_id=$1 AND command_id=$2", principal.tenant_id, str(operation_id),
                )
            if row is None:
                raise CommandNotFound("calling request was not found")
            document = _decode_document(row)
        elif isinstance(self.store, MemoryCommandStore):
            document = self._documents.get((principal.tenant_id, operation_id))
            if document is None:
                raise CommandNotFound("calling request was not found")
        else:
            raise RuntimeError("unsupported calling command store")
        operation = await self.store.get(principal.tenant_id, operation_id)
        if document.command_type == ORIGINATE:
            self._owner(document, principal)
            return document, operation
        if document.target != TARGET or document.command_type != HANGUP:
            raise CommandNotFound("calling request was not found")
        try:
            original_id = UUID(str(document.payload["origin_operation_id"]))
        except (KeyError, TypeError, ValueError):
            raise CommandNotFound("calling request was not found") from None
        if isinstance(self.store, PostgresCommandStore):
            async with self.store.pool.acquire() as conn:
                original_row = await conn.fetchrow(
                    "SELECT payload,payload_sha256 FROM middleware_commands "
                    "WHERE tenant_id=$1 AND command_id=$2",
                    principal.tenant_id, str(original_id),
                )
            if original_row is None:
                raise CommandNotFound("calling request was not found")
            original = _decode_document(original_row)
        else:
            original = self._documents.get((principal.tenant_id, original_id))
            if original is None:
                raise CommandNotFound("calling request was not found")
        self._owner(original, principal)
        original_operation = await self.store.get(principal.tenant_id, original_id)
        if (document.tenant_id != original.tenant_id
                or document.requested_by != original.requested_by
                or document.correlation_id != original.correlation_id
                or document.payload.get("actor") != original.payload.get("actor")
                or document.payload.get("originate") != original.payload.get("originate")
                or document.payload.get("authorization_reference")
                    != original.payload.get("authorization_reference")
                or document.payload.get("policy_sha256")
                    != original.payload.get("policy_sha256")
                or document.payload.get("call_id")
                    != original_operation.provider_operation_id):
            raise CommandNotFound("calling request was not found")
        return document, operation

    async def replay(self, principal: CallPrincipal, body: OriginateRequest,
                     correlation_id: str) -> CommandOperation | None:
        try:
            document, operation = await self.get(principal, operation_identity(principal, body.idempotency_key))
        except CommandNotFound:
            return None
        if (document.payload.get("originate") != body.payload()
                or document.idempotency_key != body.idempotency_key
                or document.correlation_id != correlation_id):
            raise CommandConflict("calling idempotency key was reused with different content")
        return operation.model_copy(update={"duplicate": True})

    async def originate(self, principal: CallPrincipal, body: OriginateRequest,
                        correlation_id: str, grant: CallingGrant) -> CommandOperation:
        command = CommandEnvelope(
            command_id=operation_identity(principal, body.idempotency_key),
            command_type=ORIGINATE, command_version="1.0", target=TARGET,
            tenant_id=principal.tenant_id, requested_by=principal.subject,
            correlation_id=correlation_id, idempotency_key=body.idempotency_key,
            capability=CAPABILITY,
            payload={"actor": principal.model_dump(mode="json"), "originate": body.payload(),
                     "authorization_reference": grant.authorization_reference,
                     "policy_sha256": grant.digest()},
        )
        self._validate(command)
        if isinstance(self.store, MemoryCommandStore):
            async with self._lock:
                duplicate = await self.replay(principal, body, correlation_id)
                if duplicate is not None:
                    return duplicate
                grant.authorize(principal, body, source_sha=grant.source_sha)
                for (tenant, identity), prior in self._documents.items():
                    if tenant != principal.tenant_id or prior.command_type != ORIGINATE:
                        continue
                    if prior.payload.get("authorization_reference") == grant.authorization_reference:
                        raise CommandConflict("single-call authorization was already consumed")
                    if (prior.payload["actor"]["employee_id"] == principal.employee_id
                            or prior.payload["actor"]["extension"] == principal.extension):
                        if not _terminal(await self.store.get(tenant, identity)):
                            raise CommandConflict("agent already has an active or unknown call")
                operation = await self.store.submit(command, authenticated_client_id=CLIENT_ID)
                self._documents[(principal.tenant_id, command.command_id)] = command
                return operation
        if not isinstance(self.store, PostgresCommandStore):
            raise RuntimeError("unsupported calling command store")
        # Transaction-scoped locks serialize requests across workers and hosts.
        locks = sorted({int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big", signed=True)
                        for value in (f"calling:{principal.tenant_id}:{principal.employee_id}",
                                      f"calling-phone:{principal.tenant_id}:{principal.extension}",
                                      f"calling-grant:{principal.tenant_id}:{grant.authorization_reference}")})
        async with self.store.pool.acquire() as conn:
            async with conn.transaction():
                for lock in locks:
                    await conn.execute("SELECT pg_advisory_xact_lock($1)", lock)
                existing = await conn.fetchrow(
                    "SELECT * FROM middleware_commands WHERE tenant_id=$1 AND "
                    "(command_id=$2 OR idempotency_key=$3)",
                    principal.tenant_id, str(command.command_id), command.idempotency_key,
                )
                if existing is not None:
                    # The established store checks the full authenticated digest.
                    return await self.store.submit_on_connection(
                        conn, command, authenticated_client_id=CLIENT_ID,
                    )
                grant.authorize(principal, body, source_sha=grant.source_sha)
                consumed = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM middleware_commands WHERE tenant_id=$1 "
                    "AND command_type=$2 AND payload #>> '{payload,authorization_reference}'=$3)",
                    principal.tenant_id, ORIGINATE, grant.authorization_reference,
                )
                if consumed:
                    raise CommandConflict("single-call authorization was already consumed")
                candidates = await conn.fetch(
                    "SELECT c.*, (SELECT result_payload FROM middleware_command_attempts a "
                    "WHERE a.tenant_id=c.tenant_id AND a.command_id=c.command_id "
                    "ORDER BY attempt_number DESC LIMIT 1) AS calling_evidence, "
                    "(SELECT metadata->>'readback_evidence_sha256' FROM middleware_command_audit a "
                    "WHERE a.tenant_id=c.tenant_id AND a.command_id=c.command_id "
                    "AND new_state='completed' ORDER BY id DESC LIMIT 1) AS calling_digest "
                    "FROM middleware_commands c WHERE c.tenant_id=$1 AND c.command_type=$2 "
                    "AND (c.payload #>> '{payload,actor,employee_id}'=$3 OR c.payload #>> '{payload,actor,extension}'=$4) "
                    "AND c.state<>'cancelled'",
                    principal.tenant_id, ORIGINATE, principal.employee_id, principal.extension,
                )
                for row in candidates:
                    evidence, digest = verify_readback_evidence_digest(row["calling_evidence"], row["calling_digest"])
                    prior_operation = self.store._operation(row, readback_evidence=evidence,
                                                            readback_evidence_sha256=digest)
                    if not _terminal(prior_operation):
                        raise CommandConflict("agent already has an active or unknown call")
                return await self.store.submit_on_connection(conn, command, authenticated_client_id=CLIENT_ID)

    async def reconcile(self, principal: CallPrincipal, operation_id: UUID, *,
                        key: str, expected_version: int, reason: str) -> CommandOperation:
        _, current = await self.get(principal, operation_id)
        if current.state in {"persisted", "queued", "completed", "cancelled"}:
            if current.resource_version != expected_version:
                raise CommandConflict("expected_version is stale")
            return current
        # The established reconciliation outbox performs READBACK, not originate.
        return await self.commands.mutate_operation(
            principal.tenant_id, operation_id, action="reconcile", actor_id=principal.subject,
            idempotency_key=key, expected_version=expected_version, reason=reason,
        )

    async def hangup(self, principal: CallPrincipal, operation_id: UUID, *,
                     key: str, expected_version: int, reason: str) -> CommandOperation:
        original, current = await self.get(principal, operation_id)
        if original.command_type != ORIGINATE:
            raise CommandConflict("hangup must reference an originate operation")
        # Expiring the start grant must not remove the owner's ability to end
        # that same call. No new originate authority is granted by this method.
        if not current.provider_operation_id:
            raise CommandConflict("call identity is unknown; reconcile before hangup")
        command = CommandEnvelope(
            command_id=operation_identity(principal, key), command_type=HANGUP,
            command_version="1.0", target=TARGET, tenant_id=principal.tenant_id,
            requested_by=principal.subject, correlation_id=original.correlation_id,
            idempotency_key=key, capability=CAPABILITY,
            payload={"actor": original.payload["actor"], "originate": original.payload["originate"],
                     "origin_operation_id": str(operation_id), "call_id": current.provider_operation_id,
                     "authorization_reference": original.payload["authorization_reference"],
                     "policy_sha256": original.payload["policy_sha256"], "reason": reason},
        )
        self._validate(command)
        try:
            await self.store.get(principal.tenant_id, command.command_id)
        except CommandNotFound:
            if _terminal(current):
                raise CommandConflict("call is already terminal")
            if current.resource_version != expected_version:
                raise CommandConflict("expected_version is stale")
        # The store checks the complete duplicate payload, including the call ID.
        operation = await self.store.submit(
            command, authenticated_client_id=CLIENT_ID,
        )
        if isinstance(self.store, MemoryCommandStore):
            self._documents[(principal.tenant_id, command.command_id)] = command
        return operation


def operation_response(
    operation: CommandOperation,
    document: CommandEnvelope | None = None,
) -> dict[str, Any]:
    # The merged Odoo client accepts only attempting, unknown and blocked.
    # A durable queue acknowledgement is deliberately NOT attempting/answered.
    dialing = "unknown"
    reason = "request persisted; awaiting authoritative call outcome"
    if operation.state in {"accepted", "readback_pending"} and operation.provider_operation_id:
        dialing, reason = "attempting", "telephony adapter accepted the call operation"
    elif operation.state == "cancelled":
        dialing, reason = "blocked", "request cancelled before dispatch"
    evidence_operation_id = None
    if document is not None and document.command_type == HANGUP:
        evidence_operation_id = str(document.payload.get("origin_operation_id", ""))
    elif document is not None and document.command_type != ORIGINATE:
        evidence_operation_id = "invalid"
    if _terminal(operation, evidence_operation_id=evidence_operation_id):
        reason = "terminal call outcome reconciled; see call_state"
    evidence = operation.readback_evidence or {}
    return {
        "operation_id": str(operation.command_id), "correlation_id": operation.correlation_id,
        "dialing": dialing, "reason": reason, "call_id": operation.provider_operation_id,
        "operation_state": operation.state, "call_state": evidence.get("call_state"),
        "resource_version": operation.resource_version, "duplicate": operation.duplicate,
        "retry_safe": operation.state == "cancelled", "external_dialing": False,
        "status_url": f"/v1/telephony/calls/requests/{operation.command_id}",
    }
