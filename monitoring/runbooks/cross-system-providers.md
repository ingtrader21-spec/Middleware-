# Cross-system provider alerts

## Meaning

These alerts indicate an unavailable provider adapter, elevated failures, queue pressure, stale execution, dead letters, or reconciliation mismatch for Qwen, VICIdial, or Postiz.

## Immediate checks

Inspect service health, queue depth, recent failures, retry class, and reconciliation records. Use read-only logs and metrics only; never contact a provider from a diagnostic shell.

## Safe diagnostic commands

```sh
docker compose ps
curl -fsS http://localhost:8000/health
promtool check rules monitoring/middleware-alerts.yaml
```

## Escalation and rollback

Escalate critical alerts to the middleware owner. Disable the relevant provider feature flag and leave all workflows inactive if failures persist. Do not enable dialing, messaging, publishing, or payments during diagnosis.

## Evidence and customer impact

Record timestamps, alert name, aggregate metrics, and sanitized execution IDs in the approved evidence directory. Determine customer impact from canonical middleware audit state; synthetic tests must report zero customer contact.
