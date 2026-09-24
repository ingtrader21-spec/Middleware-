# Step 4 SMS API Test Evidence

Date: 2026-08-30

## Focused contract evidence

```text
python -m pytest tests/test_communications_email.py tests/test_communications_sms.py tests/test_canonical_contracts.py -q
18 passed
```

The suite verifies API/schema rejection, caller scope, tenant isolation,
approved sender enforcement, E.164 validation, exact idempotency, conflicting
replay, GSM-7/UCS-2 accounting, consent and opt-out suppression, idempotent
cancellation, usage readback, signed DLR replay, monotonic status, inbound MO,
STOP/HELP effects, and unknown-outcome quarantine.

## Full source evidence

```text
bash scripts/run_ci.sh
171 passed, 23 skipped, 38 warnings, 11 subtests passed
RUNTIME_CONTRACT_ROUTES=PASS
PROJECT_SPECIFIC_CI=PASS
```

## Temporal duplicate-send evidence

```text
bash scripts/temporal_integration_ci.sh
1 passed
TEMPORAL_SMS_UNKNOWN_OUTCOME_NO_RETRY=PASS
```

The SMS workflow fixture injects a possible-after-acceptance timeout. The
command transitions to `reconciliation_required`, performs exactly one provider
execution attempt, performs no blind retry, and is not marked complete.

GitHub exact-head and merge-result CI are the authoritative Docker,
PostgreSQL/Redis, NATS JetStream, synthetic acceptance, and container-security
evidence for the pushed PR head.
