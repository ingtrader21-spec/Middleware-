from __future__ import annotations

import asyncio
import hmac
import json
from collections.abc import Mapping
from typing import Any, Protocol
from uuid import UUID

import asyncpg
from temporalio import activity
from temporalio.exceptions import ApplicationError

from .commands import (
    AUTHENTICATED_CLIENT_ID_KEY,
    CommandConflict,
    CommandEnvelope,
    CommandNotFound,
    PostgresCommandStore,
    authenticated_command_digest,
    verify_readback_evidence_digest,
)
from .klyrow_alert_adapter import KlyrowAlertAdapter, KlyrowAlertAdapterError
from .odoo_provider_adapter import OdooProviderAdapter, OdooProviderAdapterError
from .klyrow_email_adapter import KlyrowEmailAdapter, KlyrowEmailAdapterError
from .postly_social_adapter import (
    PostlySocialAdapter,
    PostlySocialAdapterError,
    PostlySocialUnknownOutcomeError,
)
from .telnexa_provider_adapter import (
    TelnexaProviderAdapterError,
    TelnexaSmsAdapter,
)
from .provider_canary import provider_evidence_digest
from .calling_contract import (
    HANGUP, ORIGINATE, TARGET, CallLifecycleEvidence, validate_call_evidence,
)
from .vicidial_internal_call_adapter import (
    VicidialInternalCallAdapter, VicidialInternalCallError,
    VicidialInternalCallPreDispatchRejected, VicidialInternalCallUnknown,
)
from .temporal_workflows import (
    ActivityResult,
    CommandExecutionRequest,
    CommandTransitionRequest,
    DeadLetterReplayRequest,
    DelayedCallbackRequest,
    OriginalCallCompletionRequest,
    ProvisioningStepRequest,
    ReconciliationRequest,
)


class ProviderAdapter(Protocol):
    async def execute(self, request: CommandExecutionRequest) -> ActivityResult:
        ...

    async def readback(self, request: CommandExecutionRequest) -> ActivityResult:
        ...


class FailClosedWorkflowActivities:
    """Activity bindings used until a durable command/operation owns execution."""

    @staticmethod
    def _blocked(name: str) -> ApplicationError:
        return ApplicationError(
            f"{name} is not bound to the durable command ledger",
            non_retryable=True,
            type="CapabilityDisabled",
        )

    @activity.defn(name="dispatch_delayed_callback")
    async def dispatch_delayed_callback(self, request: DelayedCallbackRequest) -> Any:
        raise self._blocked("dispatch_delayed_callback")

    @activity.defn(name="provision_identity")
    async def provision_identity(self, request: ProvisioningStepRequest) -> Any:
        raise self._blocked("provision_identity")

    @activity.defn(name="provision_product")
    async def provision_product(self, request: ProvisioningStepRequest) -> Any:
        raise self._blocked("provision_product")

    @activity.defn(name="verify_provisioning")
    async def verify_provisioning(self, request: ProvisioningStepRequest) -> Any:
        raise self._blocked("verify_provisioning")

    @activity.defn(name="compensate_provisioning")
    async def compensate_provisioning(self, request: ProvisioningStepRequest) -> Any:
        raise self._blocked("compensate_provisioning")

    @activity.defn(name="replay_dead_letter")
    async def replay_dead_letter(self, request: DeadLetterReplayRequest) -> Any:
        raise self._blocked("replay_dead_letter")

    def registered(self) -> tuple[Any, ...]:
        return (
            self.dispatch_delayed_callback,
            self.provision_identity,
            self.provision_product,
            self.verify_provisioning,
            self.compensate_provisioning,
            self.replay_dead_letter,
        )


class CommandLedgerWorkflowActivities:
    def __init__(
        self,
        store: PostgresCommandStore,
        odoo: OdooProviderAdapter | None = None,
        klyrow_alert: KlyrowAlertAdapter | None = None,
        telnexa_sms: TelnexaSmsAdapter | None = None,
        klyrow_email: KlyrowEmailAdapter | None = None,
        postly_social: PostlySocialAdapter | None = None,
        vicidial_internal: VicidialInternalCallAdapter | None = None,
    ) -> None:
        self.store = store
        self.odoo = odoo
        self.klyrow_alert = klyrow_alert
        self.telnexa_sms = telnexa_sms
        self.klyrow_email = klyrow_email
        self.postly_social = postly_social
        self.vicidial_internal = vicidial_internal

    @activity.defn(name="record_command_transition")
    async def record_command_transition(
        self,
        request: CommandTransitionRequest,
    ) -> ActivityResult:
        if (request.readback_evidence is not None
                and request.new_state == "reconciliation_required"):
            try:
                observed = CallLifecycleEvidence.model_validate(
                    request.readback_evidence
                )
            except (TypeError, ValueError) as exc:
                raise ApplicationError(
                    "nonterminal calling evidence failed the bounded contract",
                    non_retryable=True, type="CommandTransitionRejected",
                ) from exc
            if observed.terminal:
                raise ApplicationError(
                    "terminal calling evidence cannot be stored as nonterminal",
                    non_retryable=True, type="CommandTransitionRejected",
                )
        try:
            operation = await self.store.transition(
                request.tenant_id,
                UUID(request.command_id),
                new_state=request.new_state,  # type: ignore[arg-type]
                actor_id=request.actor_id,
                reason=request.reason,
                provider_operation_id=request.provider_operation_id,
                readback_evidence=request.readback_evidence,
            )
        except (ValueError, CommandConflict, CommandNotFound) as exc:
            raise ApplicationError(
                str(exc),
                non_retryable=True,
                type="CommandTransitionRejected",
            ) from exc
        return ActivityResult(
            status=operation.state,
            detail=request.reason,
            provider_operation_id=operation.provider_operation_id,
            readback_evidence=operation.readback_evidence,
        )

    def _adapter(self, request: CommandExecutionRequest) -> ProviderAdapter:
        if request.target == "odoo-19" and self.odoo is not None:
            return self.odoo
        if request.target == "klyrow-alert-email" and self.klyrow_alert is not None:
            return self.klyrow_alert
        if request.target == "telnexa-sms" and self.telnexa_sms is not None:
            return self.telnexa_sms
        if request.target == "klyrow-email" and self.klyrow_email is not None:
            return self.klyrow_email
        if request.target == "postly-social" and self.postly_social is not None:
            return self.postly_social
        if (request.target == TARGET and request.command_type in {ORIGINATE, HANGUP}
                and self.vicidial_internal is not None):
            return self.vicidial_internal
        raise ApplicationError(
            "no production provider adapter is activated for this command",
            non_retryable=True,
            type="CapabilityDisabled",
        )

    @activity.defn(name="execute_command")
    async def execute_command(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        if request.target == TARGET:
            request = await self._load_durable_execution_request(request)
        adapter = self._adapter(request)
        if request.target == TARGET:
            claimed = await self._claim_call_dispatch(request)
            if not claimed:
                cancelled = await self._load_committed_call_cancellation(request)
                if cancelled is not None:
                    return cancelled
                # A previous process may have sent the mutation. Readback is
                # the only safe continuation; never originate/hang up again.
                return await adapter.readback(request)
        try:
            return await adapter.execute(request)
        except VicidialInternalCallPreDispatchRejected:
            # Do not acknowledge the proven no-send outcome until the same
            # activity has durably cancelled the claimed attempt. If this
            # transaction fails, Temporal observes an activity failure rather
            # than a transient status that could be lost before cancellation.
            for attempt in range(3):
                try:
                    return await self.record_call_pre_dispatch_rejection(request)
                except (asyncpg.PostgresConnectionError, asyncpg.InterfaceError,
                        asyncpg.SerializationError, asyncpg.DeadlockDetectedError,
                        asyncpg.CannotConnectNowError, ConnectionError, TimeoutError):
                    if attempt == 2:
                        raise
                    # Retain the proven rejection in this owning activity;
                    # retry only the idempotent transaction, never the adapter.
                    await asyncio.sleep(0.1 * (2 ** attempt))
            raise RuntimeError("pre-dispatch rejection persistence did not complete")
        except PostlySocialUnknownOutcomeError as exc:
            # Postly has no idempotency key. Retrying an ambiguous publish
            # could put a second post on a real account, so this outcome must
            # reach an operator instead of the retry policy.
            raise ApplicationError(
                str(exc),
                non_retryable=True,
                type="ProviderOutcomeUnknown",
            ) from exc
        except VicidialInternalCallUnknown as exc:
            raise ApplicationError(
                str(exc), non_retryable=True, type="ProviderOutcomeUnknown",
            ) from exc
        except (
            OdooProviderAdapterError,
            KlyrowAlertAdapterError,
            TelnexaProviderAdapterError,
            KlyrowEmailAdapterError,
            PostlySocialAdapterError,
            VicidialInternalCallError,
        ) as exc:
            raise ApplicationError(
                str(exc),
                type="ProviderAdapterError",
            ) from exc

    @activity.defn(name="record_call_pre_dispatch_rejection")
    async def record_call_pre_dispatch_rejection(
        self, request: CommandExecutionRequest,
    ) -> ActivityResult:
        """Atomically persist the claimed, conclusively unsent call outcome."""
        durable = await self._load_durable_execution_request(request)
        if durable.command_type != ORIGINATE or durable.target != TARGET:
            raise ApplicationError(
                "pre-dispatch rejection is restricted to bounded originate",
                non_retryable=True, type="CommandExecutionRejected",
            )
        async with self.store.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT state FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2 FOR UPDATE",
                    durable.tenant_id, durable.command_id,
                )
                attempt = await conn.fetchrow(
                    "SELECT id, state, result_payload, error_code FROM middleware_command_attempts "
                    "WHERE tenant_id=$1 AND command_id=$2 ORDER BY attempt_number DESC LIMIT 1 FOR UPDATE",
                    durable.tenant_id, durable.command_id,
                )
                if (row is not None and attempt is not None
                        and row["state"] == "cancelled"
                        and attempt["state"] == "failed"
                        and attempt["error_code"] == "pre_dispatch_rejected"
                        and self._is_dispatch_claim(attempt["result_payload"])):
                    return ActivityResult(
                        "cancelled", "bounded originate rejected before transport",
                    )
                if (row is None or attempt is None or row["state"] != "dispatching"
                        or not self._is_dispatch_claim(attempt["result_payload"])):
                    raise ApplicationError(
                        "pre-dispatch rejection does not own the durable dispatch claim",
                        non_retryable=True, type="CommandExecutionRejected",
                    )
                await conn.execute(
                    "UPDATE middleware_commands SET state='cancelled', resource_version=resource_version+1, "
                    "cancelled_at=now(), cancellation_reason=$3, updated_at=now() "
                    "WHERE tenant_id=$1 AND command_id=$2",
                    durable.tenant_id, durable.command_id,
                    "bounded originate rejected before transport",
                )
                await conn.execute(
                    "UPDATE middleware_command_attempts SET state='failed', "
                    "error_code='pre_dispatch_rejected', error_detail=$2, finished_at=now() WHERE id=$1",
                    attempt["id"],
                    "bounded originate rejected before transport",
                )
                await conn.execute(
                    "INSERT INTO middleware_command_audit "
                    "(tenant_id,command_id,previous_state,new_state,actor_id,reason,metadata) "
                    "VALUES ($1,$2,'dispatching','cancelled',$3,$4,'{\"external_effect\":false}'::jsonb)",
                    durable.tenant_id, durable.command_id,
                    "temporal:codestra.calling-dispatch.v1",
                    "bounded originate rejected before transport",
                )
        return ActivityResult("cancelled", "bounded originate rejected before transport")

    @activity.defn(name="readback_command")
    async def readback_command(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        adapter = self._adapter(request)
        try:
            return await adapter.readback(request)
        except (
            OdooProviderAdapterError,
            KlyrowAlertAdapterError,
            TelnexaProviderAdapterError,
            KlyrowEmailAdapterError,
            PostlySocialAdapterError,
            VicidialInternalCallError,
        ) as exc:
            raise ApplicationError(
                str(exc),
                type="ProviderReadbackError",
            ) from exc

    @activity.defn(name="recover_call_execution")
    async def recover_call_execution(
        self, request: CommandExecutionRequest,
    ) -> ActivityResult:
        """Read committed no-send proof after a lost activity acknowledgement."""
        durable = await self._load_durable_execution_request(request)
        if durable.target != TARGET or durable.command_type != ORIGINATE:
            raise ApplicationError(
                "execution recovery is restricted to bounded originate",
                non_retryable=True, type="CommandExecutionRejected",
            )
        return (await self._load_committed_call_cancellation(durable)
                or ActivityResult("reconciliation_required", "no committed no-send proof"))

    async def _load_durable_execution_request(
        self, request: CommandExecutionRequest,
    ) -> CommandExecutionRequest:
        try:
            operation_id = UUID(request.command_id)
        except ValueError as exc:
            raise ApplicationError("command identity is invalid", non_retryable=True,
                                   type="CommandExecutionRejected") from exc
        async with self.store.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
                request.tenant_id, request.command_id,
            )
        if row is None:
            raise ApplicationError("durable command was not found", non_retryable=True,
                                   type="CommandExecutionRejected")
        durable, digest = self._validated_reconciliation_command(
            row,
            ReconciliationRequest(request.command_id, request.tenant_id, "dispatch validation"),
            operation_id,
        )
        if durable != request or not hmac.compare_digest(
            digest, authenticated_command_digest(
                CommandEnvelope.model_validate({
                    key: getattr(request, key) for key in (
                        "command_id", "command_type", "command_version", "target",
                        "tenant_id", "requested_by", "correlation_id",
                        "idempotency_key", "capability", "payload",
                    )
                }), request.authenticated_client_id,
            ),
        ):
            raise ApplicationError("Temporal command differs from durable intent",
                                   non_retryable=True, type="CommandExecutionRejected")
        return durable

    async def _claim_call_dispatch(self, request: CommandExecutionRequest) -> bool:
        """Atomically elect the only process allowed to send a call mutation."""
        async with self.store.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE middleware_command_attempts
                SET result_payload='{"dispatch_claimed":true}'::jsonb
                WHERE id=(SELECT id FROM middleware_command_attempts
                          WHERE tenant_id=$1 AND command_id=$2
                          ORDER BY attempt_number DESC LIMIT 1)
                  AND state='dispatching'
                  AND result_payload IS NULL
                RETURNING id
                """,
                request.tenant_id, request.command_id,
            )
        return row is not None

    @staticmethod
    def _is_dispatch_claim(value: Any) -> bool:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return False
        return isinstance(value, Mapping) and dict(value) == {"dispatch_claimed": True}

    async def _load_committed_call_cancellation(
        self, request: CommandExecutionRequest,
    ) -> ActivityResult | None:
        """Recover a proven no-send cancellation without readback or redial."""
        async with self.store.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT c.state, a.state AS attempt_state, a.error_code, "
                "a.result_payload FROM middleware_commands c "
                "JOIN LATERAL (SELECT state,error_code,result_payload "
                "FROM middleware_command_attempts WHERE tenant_id=c.tenant_id "
                "AND command_id=c.command_id ORDER BY attempt_number DESC LIMIT 1) a ON true "
                "WHERE c.tenant_id=$1 AND c.command_id=$2",
                request.tenant_id, request.command_id,
            )
        if (row is not None and row["state"] == "cancelled"
                and row["attempt_state"] == "failed"
                and row["error_code"] == "pre_dispatch_rejected"
                and self._is_dispatch_claim(row["result_payload"])):
            return ActivityResult(
                "cancelled", "bounded originate rejected before transport",
            )
        return None

    @staticmethod
    def _validated_reconciliation_command(
        row: Mapping[str, Any],
        request: ReconciliationRequest,
        operation_id: UUID,
    ) -> tuple[CommandExecutionRequest, str]:
        durable = row["payload"]
        if isinstance(durable, str):
            try:
                durable = json.loads(durable)
            except ValueError as exc:
                raise ApplicationError(
                    "durable command payload is invalid JSON",
                    non_retryable=True,
                    type="ReconciliationRejected",
                ) from exc
        if not isinstance(durable, Mapping):
            raise ApplicationError(
                "durable command payload is malformed",
                non_retryable=True,
                type="ReconciliationRejected",
            )
        value = dict(durable)
        authenticated_client_id = value.pop(AUTHENTICATED_CLIENT_ID_KEY, None)
        if not isinstance(authenticated_client_id, str) or not authenticated_client_id:
            raise ApplicationError(
                "durable command is missing authenticated client provenance",
                non_retryable=True,
                type="ReconciliationRejected",
            )
        try:
            command = CommandEnvelope.model_validate(value)
        except Exception as exc:
            raise ApplicationError(
                "durable command does not match the canonical envelope",
                non_retryable=True,
                type="ReconciliationRejected",
            ) from exc
        if command.command_id != operation_id or command.tenant_id != request.tenant_id:
            raise ApplicationError(
                "reconciliation identity does not match the durable command",
                non_retryable=True,
                type="ReconciliationRejected",
            )

        expected_digest = authenticated_command_digest(
            command,
            authenticated_client_id,
        )
        persisted_digest = row.get("payload_sha256")
        if (
            not isinstance(persisted_digest, str)
            or not hmac.compare_digest(persisted_digest, expected_digest)
        ):
            raise ApplicationError(
                "durable command payload digest does not match submission evidence",
                non_retryable=True,
                type="ReconciliationRejected",
            )

        return (
            CommandExecutionRequest(
                **command.model_dump(mode="json"),
                authenticated_client_id=authenticated_client_id,
            ),
            expected_digest,
        )

    async def _load_reconciliation_command(
        self,
        request: ReconciliationRequest,
    ) -> tuple[CommandExecutionRequest | None, ActivityResult | None, str | None]:
        try:
            operation_id = UUID(request.operation_id)
        except ValueError as exc:
            raise ApplicationError(
                "reconciliation operation_id is invalid",
                non_retryable=True,
                type="ReconciliationRejected",
            ) from exc

        async with self.store.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM middleware_commands
                WHERE tenant_id=$1 AND command_id=$2
                """,
                request.tenant_id,
                str(operation_id),
            )
        if row is None:
            raise ApplicationError(
                "reconciliation operation was not found",
                non_retryable=True,
                type="ReconciliationRejected",
            )
        if row["state"] == "completed":
            operation = await self.store.get(request.tenant_id, operation_id)
            command, payload_digest = self._validated_reconciliation_command(
                row, request, operation_id,
            )
            return command, ActivityResult(
                status="completed",
                detail="provider read-back was already durably reconciled",
                provider_operation_id=operation.provider_operation_id,
                readback_evidence=operation.readback_evidence,
            ), payload_digest
        if row["state"] != "reconciliation_required":
            raise ApplicationError(
                "operation is not awaiting reconciliation",
                non_retryable=True,
                type="ReconciliationRejected",
            )

        command, payload_digest = self._validated_reconciliation_command(
            row,
            request,
            operation_id,
        )
        return command, None, payload_digest

    async def _persist_reconciliation_result(
        self,
        request: ReconciliationRequest,
        result: ActivityResult,
        expected_payload_sha256: str,
    ) -> ActivityResult:
        if result.status not in {"matched", "mismatch"}:
            raise ApplicationError(
                "provider read-back returned an unsupported status",
                non_retryable=True,
                type="ProviderReadbackContractError",
            )
        safe_detail = result.detail[:2048]
        provider_operation_id = result.provider_operation_id or request.operation_id
        evidence = result.readback_evidence or {
            "schema_version": "1.0",
            "status": result.status,
            "provider_operation_id": provider_operation_id,
        }
        evidence_digest = provider_evidence_digest(evidence)
        actor = "temporal:codestra.reconciliation.v1"
        matched = result.status == "matched"

        async with self.store.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """
                    SELECT * FROM middleware_commands
                    WHERE tenant_id=$1 AND command_id=$2
                    FOR UPDATE
                    """,
                    request.tenant_id,
                    request.operation_id,
                )
                if current is None:
                    raise ApplicationError(
                        "reconciliation operation was not found",
                        non_retryable=True,
                        type="ReconciliationRejected",
                    )
                if current["state"] == "completed" and matched:
                    durable = await conn.fetchrow(
                        """
                        SELECT
                          (SELECT result_payload FROM middleware_command_attempts
                           WHERE tenant_id=$1 AND command_id=$2
                           ORDER BY attempt_number DESC LIMIT 1) AS evidence,
                          (SELECT metadata->>'readback_evidence_sha256'
                           FROM middleware_command_audit
                           WHERE tenant_id=$1 AND command_id=$2
                             AND new_state='completed'
                             AND metadata ? 'readback_evidence_sha256'
                           ORDER BY id DESC LIMIT 1) AS evidence_digest
                        """,
                        request.tenant_id, request.operation_id,
                    )
                    if durable is None:
                        raise ApplicationError(
                            "completed reconciliation evidence is unavailable",
                            non_retryable=True, type="ReconciliationRejected",
                        )
                    if not isinstance(durable["evidence_digest"], str):
                        raise ApplicationError(
                            "completed reconciliation evidence digest is unavailable",
                            non_retryable=True, type="ReconciliationRejected",
                        )
                    try:
                        committed, _ = verify_readback_evidence_digest(
                            durable["evidence"], durable["evidence_digest"],
                        )
                    except RuntimeError as exc:
                        raise ApplicationError(
                            "completed reconciliation evidence failed integrity verification",
                            non_retryable=True, type="ReconciliationRejected",
                        ) from exc
                    if committed is None or not hmac.compare_digest(
                        provider_evidence_digest(committed), evidence_digest,
                    ):
                        raise ApplicationError(
                            "replacement reconciliation evidence conflicts with the durable result",
                            non_retryable=True, type="ReconciliationRejected",
                        )
                    return ActivityResult(
                        status="completed",
                        detail="provider read-back was already durably reconciled",
                        provider_operation_id=current["provider_operation_id"],
                        readback_evidence=committed,
                    )
                if current["state"] != "reconciliation_required":
                    raise ApplicationError(
                        "operation is no longer awaiting reconciliation",
                        non_retryable=True,
                        type="ReconciliationRejected",
                    )

                try:
                    operation_id = UUID(request.operation_id)
                except ValueError as exc:
                    raise ApplicationError(
                        "reconciliation operation_id is invalid",
                        non_retryable=True,
                        type="ReconciliationRejected",
                    ) from exc
                current_command, current_payload_sha256 = self._validated_reconciliation_command(
                    current,
                    request,
                    operation_id,
                )
                if not hmac.compare_digest(
                    current_payload_sha256,
                    expected_payload_sha256,
                ):
                    raise ApplicationError(
                        "durable command changed during provider reconciliation",
                        non_retryable=True,
                        type="ReconciliationRejected",
                    )

                if current_command.target == TARGET:
                    observed_id = evidence.get("asterisk_uniqueid")
                    expected_ids = (current["provider_operation_id"], result.provider_operation_id,
                                    current_command.payload.get("call_id"))
                    if any(value is not None and value != observed_id for value in expected_ids):
                        raise ApplicationError(
                            "calling evidence differs from the accepted provider identity",
                            non_retryable=True, type="ProviderReadbackContractError",
                        )
                next_state = "completed" if matched else "reconciliation_required"
                if matched:
                    row = await conn.fetchrow(
                        """
                        UPDATE middleware_commands
                        SET state='completed',
                            provider_operation_id=COALESCE($3, provider_operation_id),
                            last_error=NULL,
                            completed_at=now(),
                            updated_at=now(),
                            resource_version=resource_version+1
                        WHERE tenant_id=$1 AND command_id=$2
                        RETURNING *
                        """,
                        request.tenant_id,
                        request.operation_id,
                        provider_operation_id,
                    )
                else:
                    row = await conn.fetchrow(
                        """
                        UPDATE middleware_commands
                        SET provider_operation_id=COALESCE($3, provider_operation_id),
                            last_error=$4,
                            reconciliation_reason=$4,
                            updated_at=now(),
                            resource_version=resource_version+1
                        WHERE tenant_id=$1 AND command_id=$2
                        RETURNING *
                        """,
                        request.tenant_id,
                        request.operation_id,
                        provider_operation_id,
                        safe_detail,
                    )
                assert row is not None
                metadata = json.dumps(
                    {
                        "provider_operation_id": provider_operation_id,
                        "readback_evidence_sha256": evidence_digest,
                        "reconciliation_status": result.status,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
                await conn.execute(
                    """
                    INSERT INTO middleware_command_audit (
                        tenant_id, command_id, previous_state, new_state,
                        actor_id, reason, metadata
                    ) VALUES ($1,$2,'reconciliation_required',$3,$4,$5,$6::jsonb)
                    """,
                    request.tenant_id,
                    request.operation_id,
                    next_state,
                    actor,
                    safe_detail,
                    metadata,
                )
                await conn.execute(
                    """
                    UPDATE middleware_command_attempts
                    SET state=$3,
                        provider_operation_id=COALESCE($4, provider_operation_id),
                        result_payload=$5::jsonb,
                        error_code=CASE
                            WHEN $3='reconciliation_required'
                            THEN 'provider_readback_mismatch' ELSE NULL
                        END,
                        error_detail=CASE
                            WHEN $3='reconciliation_required' THEN $6 ELSE NULL
                        END,
                        finished_at=now()
                    WHERE id=(
                        SELECT id FROM middleware_command_attempts
                        WHERE tenant_id=$1 AND command_id=$2
                        ORDER BY attempt_number DESC LIMIT 1
                    )
                    """,
                    request.tenant_id,
                    request.operation_id,
                    next_state,
                    provider_operation_id,
                    json.dumps(evidence, separators=(",", ":"), sort_keys=True),
                    safe_detail,
                )
        return ActivityResult(
            status=next_state,
            detail=safe_detail,
            provider_operation_id=provider_operation_id,
            readback_evidence=evidence,
        )

    @activity.defn(name="reconcile_operation")
    async def reconcile_operation(
        self,
        request: ReconciliationRequest,
    ) -> ActivityResult:
        command, completed, payload_sha256 = await self._load_reconciliation_command(
            request
        )
        if completed is not None:
            assert command is not None
            if (command.target == TARGET and command.command_type == HANGUP
                    and completed.readback_evidence):
                await self.complete_originating_call(OriginalCallCompletionRequest(
                    command.command_id, command.tenant_id,
                    completed.readback_evidence,
                ))
            return completed
        assert command is not None
        assert payload_sha256 is not None
        result = await self.readback_command(command)
        if command.target == TARGET and command.command_type in {ORIGINATE, HANGUP}:
            original = (command.command_id if command.command_type == ORIGINATE
                        else str(command.payload.get("origin_operation_id", "")))
            try:
                evidence = validate_call_evidence(
                    result.readback_evidence, operation_id=original,
                    correlation_id=command.correlation_id, tenant_id=command.tenant_id,
                    actor=command.payload["actor"],
                    authorization_reference=command.payload["authorization_reference"],
                    require_terminal=result.status == "matched",
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ApplicationError(
                    "calling evidence failed the bounded contract",
                    non_retryable=True, type="ProviderReadbackContractError",
                ) from exc
            result = ActivityResult(
                result.status, result.detail, result.provider_operation_id, evidence,
            )
        persisted = await self._persist_reconciliation_result(
            request,
            result,
            payload_sha256,
        )
        if (command.target == TARGET and command.command_type == HANGUP
                and persisted.status == "completed"):
            await self.complete_originating_call(OriginalCallCompletionRequest(
                command.command_id, command.tenant_id,
                persisted.readback_evidence or {},
            ))
        return persisted

    @activity.defn(name="complete_originating_call")
    async def complete_originating_call(
        self, request: OriginalCallCompletionRequest,
    ) -> ActivityResult:
        try:
            hangup_id = UUID(request.hangup_command_id)
        except ValueError as exc:
            raise ApplicationError("hangup command identity is invalid", non_retryable=True,
                                   type="CommandExecutionRejected") from exc
        async with self.store.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
                request.tenant_id, request.hangup_command_id,
            )
        if row is None:
            raise ApplicationError("hangup command was not found", non_retryable=True,
                                   type="CommandExecutionRejected")
        hangup, _ = self._validated_reconciliation_command(
            row, ReconciliationRequest(request.hangup_command_id, request.tenant_id,
                                       "hangup completion"), hangup_id,
        )
        if hangup.command_type != HANGUP or hangup.target != TARGET:
            raise ApplicationError("command is not a bounded hangup", non_retryable=True,
                                   type="CommandExecutionRejected")
        original_id = str(hangup.payload.get("origin_operation_id", ""))
        original_request = ReconciliationRequest(
            original_id, request.tenant_id, "same-call hangup terminal evidence",
        )
        # A terminal same-call hangup may outrun the originate workflow's
        # readback. Move only that durable origin into its existing
        # reconciliation transition; no generic transition is broadened.
        async with self.store.pool.acquire() as conn:
            origin_state = await conn.fetchval(
                "SELECT state FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
                request.tenant_id, original_id,
            )
        if origin_state in {"accepted", "readback_pending"}:
            try:
                await self.store.transition(
                    request.tenant_id, UUID(original_id),
                    new_state="reconciliation_required",
                    actor_id="temporal:codestra.same-call-hangup.v1",
                    reason="validated terminal hangup requires originating-call reconciliation",
                )
            except CommandConflict:
                # A concurrent terminal/readback transition is reloaded and
                # validated below; it is never overwritten from local state.
                pass
        command, completed, digest = await self._load_reconciliation_command(original_request)
        if completed is not None:
            return completed
        assert command is not None and digest is not None
        evidence = validate_call_evidence(
            request.readback_evidence, operation_id=original_id,
            correlation_id=command.correlation_id, tenant_id=command.tenant_id,
            actor=command.payload["actor"],
            authorization_reference=command.payload["authorization_reference"],
            require_terminal=True,
        )
        return await self._persist_reconciliation_result(
            original_request,
            ActivityResult("matched", "same-call hangup terminal evidence verified",
                           evidence["asterisk_uniqueid"], evidence),
            digest,
        )

    def registered(self) -> tuple[Any, ...]:
        return (
            self.record_command_transition,
            self.execute_command,
            self.record_call_pre_dispatch_rejection,
            self.recover_call_execution,
            self.readback_command,
            self.reconcile_operation,
            self.complete_originating_call,
        )
