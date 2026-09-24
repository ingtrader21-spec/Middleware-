# Temporal critical workflows

Temporal owns recoverable, long-running middleware processes. It does not own live call control, authorization policy, provider truth, or n8n's external automation role.

## Registered workflows

| Workflow type | Purpose | Safety behavior |
|---|---|---|
| `codestra.reconciliation.v1` | Retry bounded provider read-back and reconcile an operation. | Five bounded activity attempts; a timeout never becomes success. |
| `codestra.delayed-callback.v1` | Persist a delay before requesting callback delivery. | Maximum delay is 30 days; delivery remains an activity behind capability policy. |
| `codestra.provisioning.v1` | Provision identity and product steps, then verify. | A failed product step invokes compensation before the workflow returns. |
| `codestra.dead-letter-recovery.v1` | Replay a dead letter through a controlled process. | Waits for an explicit operator approval signal and records the operator and reason. |
| `codestra.command-execution.v1` | Execute one durable command and verify provider truth. | Uses one adapter attempt; ambiguous results require reconciliation and completion requires matching read-back. |

Workflow code is deterministic and contains no network, filesystem, database, clock, random, or provider access. All effects are Temporal activities with bounded timeouts and retry policies.

`workers/run_temporal.py` binds command state transitions to the PostgreSQL
ledger and registers fail-closed provider activities. Calling an unbound
production activity fails with `CapabilityDisabled`; it cannot silently claim
success.

## Environment isolation

| Environment | Namespace | Task queue |
|---|---|---|
| Test/development | `codestra-test` | `codestra-test-critical` |
| Staging | `codestra-staging` | `codestra-staging-critical` |
| Production | `codestra-production` | `codestra-production-critical` |

Staging and production require a mounted CA, client certificate, client private key, and TLS server name. Plaintext Temporal connections are accepted only for an explicitly enabled disposable localhost test server.

## Verification

`tests/integration/test_temporal_workflows.py` runs against Temporal's
time-skipping test server and proves activity retry, a one-day durable timer,
provisioning compensation, operator-gated dead-letter recovery, command
read-back gating, and mismatch reconciliation.
