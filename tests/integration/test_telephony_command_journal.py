import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import httpx
from fastapi import HTTPException
from fastapi import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1.commands import (
    ReconciliationRunRequest,
    OperationRegistration,
    OperationTransition,
    TerminalResultRequest,
    create_command,
    create_reconciliation_run,
    register_operation,
    create_terminal_result,
    transition_operation,
)
from app.adapters.odoo.telephony_results import deliver_telephony_result
from app.core.telephony_commands import (
    TelephonyCommandRequest,
    payload_hash,
)
from app.db.models import (
    PolicyDecision,
    TelephonyCommandJournal,
    TelephonyOperationJournal,
)
from app.workers.telephony_commands import claim_authorized, dispatch_one


def test_command_policy_and_idempotency_are_database_authoritative():
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "rehearsal" in database_url or "diag" in database_url
    asyncio.run(_scenario(database_url))


async def _scenario(database_url: str):
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    correlation_id = f"COR-SYNTHETIC-{uuid4()}"
    idempotency_key = f"IDM-SYNTHETIC-{uuid4()}"
    decision_id = uuid4()
    context = {
        "decision_id": str(decision_id),
        "correlation_id": correlation_id,
        "allow": True,
        "enforced": True,
        "action": "sync",
        "resource": "telephony.endpoint",
        "expiration": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "authorization_scope": {
            "action": "sync",
            "subject": "AGT-SYNTHETIC-DB",
            "resource": "telephony.asterisk.endpoint.apply",
            "environment": "staging",
            "business_unit": "BU-SYNTHETIC-DB",
            "campaign": "CMP-SYNTHETIC-DB",
            "agent": "AGT-SYNTHETIC-DB",
        },
    }
    command = TelephonyCommandRequest.model_validate(
        {
            "schema_version": "1.0",
            "originating_outbox_public_id": "OUT-SYNTHETIC-DB",
            "event_id": "EVT-SYNTHETIC-DB",
            "command_type": "telephony.asterisk.endpoint.apply",
            "aggregate_type": "agent",
            "aggregate_public_id": "AGT-SYNTHETIC-DB",
            "aggregate_version": 1,
            "environment": "staging",
            "business_unit_public_id": "BU-SYNTHETIC-DB",
            "campaign_public_id": "CMP-SYNTHETIC-DB",
            "idempotency_key": idempotency_key,
            "correlation_id": correlation_id,
            "causation_id": "CAU-SYNTHETIC-DB",
            "policy_decision_id": str(decision_id),
            "policy_decision_hash": payload_hash(context),
            "payload": {
                "endpoint_public_id": "EPT-SYNTHETIC-DB",
                "agent_public_id": "AGT-SYNTHETIC-DB",
                "allocation_reservation_id": "RSV-SYNTHETIC-DB",
                "desired_state_version": 1,
            },
        }
    )
    try:
        async with factory() as session:
            session.add(
                PolicyDecision(
                    id=decision_id,
                    policy="synthetic-telephony-policy",
                    allowed=True,
                    reason="allowed",
                    correlation_id=correlation_id,
                    context=context,
                )
            )
            await session.commit()
            first = await create_command(command, idempotency_key, session)
            stored_decision = await session.get(PolicyDecision, decision_id)
            assert stored_decision is not None
            stored_decision.context = {
                **context,
                "expiration": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            }
            await session.commit()
            replay = await create_command(command, idempotency_key, session)
            assert first["state"] == "AUTHORIZED"
            assert replay["replayed"] is True
            assert replay["command_id"] == first["command_id"]
            stored_decision.context = context
            await session.commit()
            stored = await session.scalar(
                select(TelephonyCommandJournal).where(
                    TelephonyCommandJournal.correlation_id == correlation_id
                )
            )
            assert stored is not None
            assert stored.command_id == UUID(first["command_id"])

            changed = command.model_copy(update={"aggregate_version": 2})
            with pytest.raises(HTTPException) as conflict:
                await create_command(changed, idempotency_key, session)
            assert conflict.value.status_code == 409

            wrong_scope = command.model_copy(
                update={
                    "idempotency_key": f"IDM-SYNTHETIC-{uuid4()}",
                    "campaign_public_id": "CMP-SYNTHETIC-OTHER",
                    "payload": command.payload.model_copy(
                        update={"endpoint_public_id": "EPT-SYNTHETIC-OTHER"}
                    ),
                }
            )
            with pytest.raises(HTTPException, match="authorization scope mismatch"):
                await create_command(wrong_scope, wrong_scope.idempotency_key, session)

            expired_id = uuid4()
            expired_context = {
                **context,
                "decision_id": str(expired_id),
                "expiration": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            }
            session.add(
                PolicyDecision(
                    id=expired_id,
                    policy="synthetic-telephony-policy",
                    allowed=True,
                    reason="allowed",
                    correlation_id=correlation_id,
                    context=expired_context,
                )
            )
            await session.commit()
            expired = command.model_copy(
                update={
                    "idempotency_key": f"IDM-SYNTHETIC-{uuid4()}",
                    "policy_decision_id": str(expired_id),
                    "policy_decision_hash": payload_hash(expired_context),
                    "payload": command.payload.model_copy(
                        update={"endpoint_public_id": "EPT-SYNTHETIC-EXPIRED"}
                    ),
                }
            )
            with pytest.raises(HTTPException, match="policy decision expired"):
                await create_command(expired, expired.idempotency_key, session)
            assert await claim_authorized(session, environment="production") is None
            stored.state = "SUBMITTING"
            stored.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            await session.commit()

        class SyntheticClient:
            competing_claim = None

            async def dispatch(self, command_id, value, *, traceparent):
                assert value.idempotency_key == idempotency_key
                assert traceparent.startswith("00-")
                return {
                    "operation_id": str(uuid4()),
                    "operation_public_id": f"OPR-{uuid4().hex}",
                    "adapter_operation_id": f"ADP-OP-{uuid4().hex}",
                    "adapter_service_key": "codestra-telephony-adapter-staging",
                    "endpoint_id": "EPT-REGISTRY-SYNTHETIC",
                    "endpoint_version_id": "EPV-REGISTRY-SYNTHETIC",
                    "endpoint_key": "telephony.asterisk.endpoints.apply",
                    "readback_endpoint_key": "telephony.asterisk.endpoints.read",
                    "target_configuration_checksum": "sha256:" + "a" * 64,
                    "target_attested": True,
                    "desired_hash": payload_hash(value.desired_state()),
                }

            async def readback(self, value, operation, *, traceparent):
                async with factory() as competing_session:
                    self.competing_claim = await claim_authorized(
                        competing_session, environment="staging"
                    )
                return {
                    "actual": {"desired_state": value.desired_state()},
                    "actual_hash": operation["desired_hash"],
                    "readback_matches": True,
                }

        client = SyntheticClient()
        worker_result = await dispatch_one(
            factory,
            lambda: client,
            environment="staging",
            traceparent_factory=lambda: "00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )
        assert worker_result["state"] == "ODOO_RESULT_PENDING"
        assert client.competing_claim is None
        async with factory() as session:
            stored = await session.scalar(
                select(TelephonyCommandJournal).where(
                    TelephonyCommandJournal.correlation_id == correlation_id
                )
            )
            assert stored is not None
            assert stored.state == "ODOO_RESULT_PENDING"
            operation = await session.scalar(
                select(TelephonyOperationJournal).where(
                    TelephonyOperationJournal.command_id == stored.command_id
                )
            )
            assert operation is not None
            result_id = uuid4()
            terminal = TerminalResultRequest(
                schema_version="1.0",
                result_public_id=f"RES-{result_id.hex}",
                operation_public_id=operation.operation_public_id,
                command_public_id=stored.command_public_id,
                target_system="ASTERISK",
                target_resource_type="ENDPOINT",
                target_public_id="EPT-SYNTHETIC-DB",
                application_status="APPLIED",
                readback_status="READBACK_VERIFIED",
                requested_state_version=1,
                applied_state_version=1,
                observed_state_version=1,
                result_hash="1" * 64,
                application_hash="2" * 64,
                readback_hash="3" * 64,
                adapter_service_key=operation.adapter_service_key,
                adapter_configuration_checksum="sha256:" + "a" * 64,
                applied_at=datetime.now(UTC),
                readback_at=datetime.now(UTC),
                safe_summary="Synthetic endpoint applied and verified.",
                policy_hash=stored.policy_decision_hash,
                correlation_id=correlation_id,
            )
            created_result = await create_terminal_result(terminal, session)
            duplicate_result = await create_terminal_result(terminal, session)
            assert created_result["idempotency_status"] == "NEW"
            assert duplicate_result["idempotency_status"] == "DUPLICATE"
            with pytest.raises(
                HTTPException, match="IMMUTABLE_RESULT_BINDING_CONFLICT"
            ):
                await create_terminal_result(
                    terminal.model_copy(update={"readback_hash": "4" * 64}),
                    session,
                )

            class SyntheticOdooClient:
                calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

                async def request(
                    self,
                    operation: str,
                    payload: dict[str, Any],
                    **kwargs: Any,
                ) -> httpx.Response:
                    self.calls.append((operation, payload, kwargs))
                    request = httpx.Request("POST", "https://invalid")
                    if operation in {
                        "results.create",
                        "results.read",
                    }:
                        value: dict[str, Any] = {
                            "result_public_id": terminal.result_public_id
                        }
                    elif operation == "telephony.projections.read":
                        value = {
                            "observed_state_version": 1,
                            "observed_state_hash": "sha256:" + "3" * 64,
                        }
                    elif operation == "telephony.mappings.read":
                        value = {"target_public_id": "EPT-SYNTHETIC-DB"}
                    else:
                        value = {"correlation_id": correlation_id}
                    return httpx.Response(200, json=value, request=request)

            odoo_client = SyntheticOdooClient()
            readbacks = await deliver_telephony_result(
                session,
                terminal.result_public_id,
                client=odoo_client,
            )
            assert (
                readbacks["telephony.projections.read"]["observed_state_version"] == 1
            )
            assert [call[0] for call in odoo_client.calls] == [
                "results.create",
                "results.read",
                "telephony.projections.read",
                "telephony.mappings.read",
                "traces.read",
            ]
            run = await create_reconciliation_run(
                ReconciliationRunRequest(
                    environment="staging",
                    aggregate_type="agent",
                    aggregate_public_id=stored.aggregate_public_id,
                    target_system="ASTERISK",
                    classification="IN_SYNC",
                    correlation_id=correlation_id,
                ),
                session,
            )
            assert run["status"] == "REQUESTED"

            next_command = command.model_copy(
                update={
                    "aggregate_version": 2,
                    "idempotency_key": f"IDM-SYNTHETIC-{uuid4()}",
                    "payload": command.payload.model_copy(
                        update={"desired_state_version": 2}
                    ),
                }
            )
            accepted_next = await create_command(
                next_command, next_command.idempotency_key, session
            )
            assert accepted_next["aggregate_version"] == 2
            operation_registration = OperationRegistration(
                schema_version="1.0",
                operation_public_id=f"OPR-{uuid4().hex}",
                command_public_id=accepted_next["command_public_id"],
                adapter_service_key="codestra-telephony-adapter-staging",
                adapter_operation_id=f"ADP-OP-{uuid4().hex}",
                target_system="ASTERISK",
                target_resource_type="ENDPOINT",
                target_public_id="EPT-SYNTHETIC-DB",
                desired_state_version=2,
                desired_state_hash="sha256:" + "7" * 64,
                idempotency_key=f"IDM-OPR-{uuid4()}",
                correlation_id=correlation_id,
                registered_at=datetime.now(UTC),
            )
            registration_response = Response()
            registered = await register_operation(
                operation_registration, registration_response, session
            )
            duplicate_registration_response = Response()
            duplicate_registration = await register_operation(
                operation_registration, duplicate_registration_response, session
            )
            assert registration_response.status_code == 201
            assert duplicate_registration_response.status_code == 200
            assert duplicate_registration["idempotency_status"] == "DUPLICATE"
            transition_data = {
                "schema_version": "1.0",
                "command_public_id": accepted_next["command_public_id"],
                "state": "APPLYING",
                "target_system": "ASTERISK",
                "target_resource_type": "ENDPOINT",
                "target_public_id": "EPT-SYNTHETIC-DB",
                "desired_state_version": 2,
                "adapter_service_key": "codestra-telephony-adapter-staging",
                "environment": "staging",
                "correlation_id": correlation_id,
                "transition_sequence": 1,
                "occurred_at": datetime.now(UTC),
            }
            transition_hash = payload_hash(
                OperationTransition(
                    **transition_data,
                    transition_hash="0" * 64,
                ).model_dump(mode="json", exclude={"transition_hash"})
            )
            transitioned = await transition_operation(
                registered["operation_public_id"],
                OperationTransition(
                    **transition_data,
                    transition_hash=transition_hash,
                ),
                session,
            )
            assert transitioned["state"] == "APPLYING"
            with pytest.raises(
                HTTPException, match="out-of-order operation transition"
            ):
                out_of_order_base = OperationTransition(
                    **{
                        **transition_data,
                        "state": "APPLIED",
                        "transition_sequence": 3,
                        "transition_hash": "0" * 64,
                    }
                )
                await transition_operation(
                    registered["operation_public_id"],
                    out_of_order_base.model_copy(
                        update={
                            "transition_hash": payload_hash(
                                out_of_order_base.model_dump(
                                    mode="json", exclude={"transition_hash"}
                                )
                            )
                        }
                    ),
                    session,
                )

            duplicate_version = command.model_copy(
                update={
                    "aggregate_version": 2,
                    "idempotency_key": f"IDM-SYNTHETIC-{uuid4()}",
                    "payload": command.payload.model_copy(
                        update={
                            "desired_state_version": 2,
                            "endpoint_public_id": "EPT-SYNTHETIC-DUPLICATE-VERSION",
                        }
                    ),
                }
            )
            with pytest.raises(
                HTTPException, match="stale or duplicate aggregate version"
            ):
                await create_command(
                    duplicate_version, duplicate_version.idempotency_key, session
                )

            stale_version = command.model_copy(
                update={
                    "idempotency_key": f"IDM-SYNTHETIC-{uuid4()}",
                    "payload": command.payload.model_copy(
                        update={"endpoint_public_id": "EPT-SYNTHETIC-STALE-VERSION"}
                    ),
                }
            )
            with pytest.raises(
                HTTPException, match="stale or duplicate aggregate version"
            ):
                await create_command(
                    stale_version, stale_version.idempotency_key, session
                )
    finally:
        await engine.dispose()
