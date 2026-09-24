# Approved-order orchestration alerts

All diagnostics are read-only first. Keep `ORDER_ORCHESTRATION_ENABLED` and
`N8N_ORDER_DISPATCH_ENABLED` false unless the event is an explicitly approved
synthetic test. Never contact customers or enable external side effects.

## Covered alerts

`CodestraOrderFailureRateHigh`, `CodestraOrderQueueBacklog`,
`CodestraOrderExecutionStale`, `CodestraOrderDeadLetterIncrease`,
`CodestraOrderCallbackFailures`, `CodestraOrderReconciliationMismatch`,
`CodestraN8nOrderWorkflowUnavailable`, `CodestraOrderRetryRateHigh`, and
`CodestraOrderApprovalBacklog` all use this runbook.

## Meaning and immediate checks

Check Prometheus and Alertmanager state, middleware health/readiness, n8n
health, queue depth, recent audit events, and the middleware logs. Compare
canonical middleware status with n8n execution state before taking action.

Likely causes include dependency outage, queue backpressure, expired commands,
signature rejection, worker unavailability, or a reconciliation race.

Safe commands are `docker compose ps`, service health endpoints, Prometheus
query/API reads, `journalctl`/container-log reads, and the repository validation
scripts. Do not delete records, retry security failures, or change credentials.

## Escalation and safety action

Escalate critical alerts to the middleware and n8n owners when they persist for
one alert interval or indicate data divergence. If integrity is uncertain,
disable dispatch and callback delivery, preserve evidence, and follow the
middleware rollback procedure. Warning alerts may be investigated while the
system remains read-only.

## Evidence and customer impact

Record query results, alert timestamps, command/order references (not customer
data), and audit IDs under `/opt/codestra/compose/production-activation-readiness-20260802/evidence/`.
Customer impact is zero for synthetic-only validation; confirm separately
before any production activation.
