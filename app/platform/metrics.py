"""Kernel metrics (Phase 36), one registry per process.

Every label is low-cardinality by construction: ``command_family`` is the
first segment of the command type, ``adapter`` is a registered adapter id,
``state``/``result``/``reason``/``stage``/``mode`` are closed vocabularies.
No customer, phone, email, command id, operation id or correlation id is ever
a label. The exposition is merged into the private ``/metrics`` route by the
control plane (``monitoring-readonly`` / ``metrics.read``).
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class KernelMetrics:
    def __init__(self, registry: CollectorRegistry | None = None, *, service: str = "middleware-integration-api") -> None:
        self.registry = registry or CollectorRegistry()
        self.service = service
        r = self.registry
        self.commands_received = Counter("middleware_commands_received_total", "Commands received by the kernel", ["command_family"], registry=r)
        self.commands_completed = Counter("middleware_commands_completed_total", "Commands completed after a matched readback", ["command_family", "adapter"], registry=r)
        self.commands_failed = Counter("middleware_commands_failed_total", "Commands failed", ["command_family", "adapter", "result"], registry=r)
        self.commands_reconciliation_required = Counter("middleware_commands_reconciliation_required_total", "Commands parked for reconciliation", ["command_family", "adapter"], registry=r)
        self.command_duration = Histogram("middleware_command_duration_seconds", "Kernel stage latency", ["stage"], buckets=LATENCY_BUCKETS, registry=r)
        self.idempotency_duplicates = Counter("middleware_idempotency_duplicates_total", "Exact replays answered from the ledger", registry=r)
        self.policy_denials = Counter("middleware_policy_denials_total", "Policy Engine denials", ["reason"], registry=r)
        self.safety_denials = Counter("middleware_safety_denials_total", "Safety Gate denials", ["reason"], registry=r)
        self.cancellations = Counter("middleware_command_cancellations_total", "Cancellation outcomes", ["result"], registry=r)
        self.replays = Counter("middleware_command_replays_total", "Replay requests", ["mode"], registry=r)
        self.outbox_backlog = Gauge("middleware_outbox_backlog", "Outbox rows awaiting dispatch", registry=r)
        self.outbox_oldest_seconds = Gauge("middleware_outbox_oldest_seconds", "Age of the oldest pending outbox row", registry=r)
        self.active_leases = Gauge("middleware_active_leases", "Outbox rows currently leased", registry=r)
        self.lease_expirations = Counter("middleware_lease_expirations_total", "Leases reclaimed after expiry", registry=r)
        self.adapter_requests = Counter("middleware_adapter_requests_total", "Adapter invocations", ["adapter", "operation"], registry=r)
        self.adapter_failures = Counter("middleware_adapter_failures_total", "Adapter invocations that did not acknowledge", ["adapter", "operation", "result"], registry=r)
        self.adapter_latency = Histogram("middleware_adapter_latency_seconds", "Adapter latency", ["adapter", "operation"], buckets=LATENCY_BUCKETS, registry=r)
        self.circuit_breaker_state = Gauge("middleware_circuit_breaker_state", "0 closed, 1 half-open, 2 open", ["adapter"], registry=r)
        self.bulkhead_rejections = Counter("middleware_bulkhead_rejections_total", "Bulkhead rejections", ["adapter"], registry=r)
        self.dead_letters = Gauge("middleware_dead_letters", "Dead-lettered outbox rows", registry=r)
        self.reconciliation_backlog = Gauge("middleware_reconciliation_backlog", "Operations awaiting reconciliation", registry=r)
        self.reconciliation_decisions = Counter("middleware_reconciliation_decisions_total", "Reconciler decisions", ["adapter", "result"], registry=r)
        self.provider_effect_attempts = Counter("middleware_provider_effect_attempts_total", "Adapter execute calls that could create an external effect", ["adapter"], registry=r)

    def render(self) -> bytes:
        return generate_latest(self.registry)

    def breaker(self, name: str, previous: object, state: object) -> None:
        mapping = {"CLOSED": 0, "HALF_OPEN": 1, "OPEN": 2}
        self.circuit_breaker_state.labels(adapter=name).set(mapping.get(str(state), 0))
