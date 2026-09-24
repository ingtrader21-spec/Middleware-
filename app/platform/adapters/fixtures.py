"""No-effect fixture adapters.

Every fixture records what it was asked to do in memory and never contacts a
provider. ``test-syn`` is the synthetic transaction used for end-to-end
certification (TEST_SYN); the channel fixtures let development and test
environments exercise the kernel for every command family without an
external effect. Behaviour is scripted per command through
``payload["fixture"]`` (or per command id through ``scripts``) so the
failure-mode and chaos suites drive the real kernel paths:

``success`` (default), ``completed``, ``reject``, ``transient``, ``timeout``,
``crash``, ``unknown``, ``readback_mismatch``, ``readback_unavailable``,
``readback_not_found``, ``readback_unsupported``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.commands import CommandEnvelope, CommandOperation
from app.platform.adapter import (
    AdapterContext,
    AdapterReadiness,
    AdapterResult,
    BaseAdapter,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)


@dataclass
class FixtureAdapter(BaseAdapter):
    adapter_id: str = "fixture"
    provider_family: str = "fixture"
    connector_ids: tuple[str, ...] = ()
    served_capabilities: tuple[str, ...] = ()
    version: str = "1.0.0"
    supports_cancel: bool = True
    supports_status: bool = True
    safe_reexecution: bool = True
    external_effect: bool = False
    ready: bool = True
    # Scripted behaviours keyed by command id: a list of behaviours consumed per attempt.
    scripts: dict[str, list[str]] = field(default_factory=dict)
    # What a reconciliation observes for a command id (default: derived from effects).
    reconcile_as: dict[str, ReadbackStatus] = field(default_factory=dict)
    executed: list[tuple[str, int]] = field(default_factory=list)
    readbacks: list[str] = field(default_factory=list)
    reconciled: list[str] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)
    # Every "effect" the provider would have seen, by command id.
    effects: dict[str, int] = field(default_factory=dict)
    _behaviours: dict[str, str] = field(default_factory=dict)

    @property
    def provider_effects(self) -> int:
        return sum(self.effects.values())

    # --- contract -------------------------------------------------------------
    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        return AdapterReadiness(ready=self.ready, detail="fixture")

    def _behaviour(self, command_id: str, payload: dict[str, Any]) -> str:
        script = self.scripts.get(command_id)
        if script:
            value = script.pop(0)
        else:
            raw = payload.get("fixture")
            value = raw if isinstance(raw, str) else "success"
        self._behaviours[command_id] = value
        return value

    def _effect(self, command_id: str) -> None:
        self.effects[command_id] = self.effects.get(command_id, 0) + 1

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        command_id = str(command.command_id)
        self.executed.append((command_id, context.attempt))
        behaviour = self._behaviour(command_id, command.payload)
        reference = f"{self.adapter_id}:{command_id}:{context.attempt}"
        if behaviour == "transient":
            return AdapterResult(Outcome.TRANSIENT, error_class=ErrorClass.RETRYABLE_BEFORE_EFFECT, safe_error_code="fixture_transient")
        if behaviour == "reject":
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="fixture_rejected")
        if behaviour == "timeout":
            # The provider received the request (an effect exists) and the
            # transport stalls: the kernel must classify UNKNOWN.
            self._effect(command_id)
            await asyncio.sleep(context.timeout_seconds + 5)
            return AdapterResult(Outcome.COMPLETED, provider_operation_id=reference)
        if behaviour == "crash":
            self._effect(command_id)
            raise RuntimeError("fixture crashed after send")
        if behaviour == "unknown":
            self._effect(command_id)
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="fixture_unknown")
        self._effect(command_id)
        outcome = Outcome.COMPLETED if behaviour == "completed" else Outcome.ACCEPTED
        return AdapterResult(outcome, provider_operation_id=reference, safe_details={"fixture": self.adapter_id, "attempt": context.attempt})

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        command_id = str(operation.command_id)
        if self.effects.get(command_id):
            return AdapterResult(Outcome.COMPLETED, provider_operation_id=operation.provider_operation_id)
        return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="fixture_no_effect")

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        command_id = str(operation.command_id)
        self.readbacks.append(command_id)
        behaviour = self._behaviours.get(command_id, "success")
        if behaviour == "readback_mismatch":
            return ReadbackResult(ReadbackStatus.MISMATCH, provider_operation_id=operation.provider_operation_id, evidence={"fixture": "mismatch"})
        if behaviour == "readback_unavailable":
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code="fixture_readback_unavailable")
        if behaviour == "readback_not_found":
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="fixture_readback_not_found")
        if behaviour == "readback_unsupported":
            return ReadbackResult(ReadbackStatus.UNSUPPORTED, safe_error_code="readback_unsupported")
        if not self.effects.get(command_id):
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="fixture_no_effect")
        return ReadbackResult(
            ReadbackStatus.MATCHED,
            provider_operation_id=operation.provider_operation_id or f"{self.adapter_id}:{command_id}",
            evidence={"fixture": self.adapter_id, "effects": self.effects.get(command_id, 0)},
        )

    async def reconcile(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        command_id = str(operation.command_id)
        self.reconciled.append(command_id)
        observed = self.reconcile_as.get(command_id)
        if observed is None:
            observed = ReadbackStatus.MATCHED if self.effects.get(command_id) else ReadbackStatus.NOT_FOUND
        return ReadbackResult(
            observed,
            provider_operation_id=f"{self.adapter_id}:{command_id}:reconciled" if observed is ReadbackStatus.MATCHED else None,
            evidence={"fixture": self.adapter_id, "reconciled": True},
        )

    async def cancel(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        self.cancelled.append(str(operation.command_id))
        return AdapterResult(Outcome.CANCELLED)


def test_syn_adapter() -> FixtureAdapter:
    return FixtureAdapter(
        adapter_id="test-syn",
        provider_family="synthetic",
        connector_ids=("test-syn",),
        served_capabilities=("TEST_SYN_EXECUTE",),
    )


def development_fixtures() -> tuple[FixtureAdapter, ...]:
    return (
        test_syn_adapter(),
        FixtureAdapter(adapter_id="odoo-fixture", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE",)),
        FixtureAdapter(adapter_id="email-fixture", provider_family="email", connector_ids=("klyrow-email",), served_capabilities=("EMAIL_DELIVERY",)),
        FixtureAdapter(adapter_id="sms-fixture", provider_family="sms", connector_ids=("telnexa-sms",), served_capabilities=("SMS_DELIVERY",)),
        FixtureAdapter(adapter_id="telephony-fixture", provider_family="telephony", connector_ids=("vicidial-restricted",), served_capabilities=("INTERNAL_TELEPHONY_CALLS", "PRODUCTION_DIALING")),
        FixtureAdapter(adapter_id="crawler-fixture", provider_family="crawler", connector_ids=("kyqra-crawler",), served_capabilities=("CRAWLER_EXECUTION",)),
        FixtureAdapter(adapter_id="social-fixture", provider_family="social", connector_ids=("postly-social",), served_capabilities=("SOCIAL_PUBLISH",)),
        FixtureAdapter(adapter_id="provisioning-fixture", provider_family="provisioning", connector_ids=("provisioning-service",), served_capabilities=("PROVISIONING_WRITE",)),
        FixtureAdapter(adapter_id="n8n-fixture", provider_family="n8n", connector_ids=("n8n-automation",), served_capabilities=("N8N_WORKFLOW_DISPATCH",)),
    )
