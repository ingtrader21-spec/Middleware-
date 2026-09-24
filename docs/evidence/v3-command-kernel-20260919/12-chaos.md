# 12 — Chaos matrix

| Case | Test | Result |
|---|---|---|
| A DB fails before acceptance | test_platform_api::test_chaos_a_… | 503, nothing persisted |
| B rollback | integration::test_chaos_b_… | no orphan command/audit/intent; retry is a clean acceptance |
| C worker crash after lease before adapter | kernel::test_chaos_worker_crash_after_lease… + integration lease expiry | reclaimed after expiry, one effect |
| D crash during adapter request | kernel::…_during_adapter_request… + integration::test_lease_expiry_recovers_by_readback_without_resend | readback first, no resend |
| E Redis unavailable | kernel does not depend on Redis (replay guard = webhook ingress only); worker role builds without Redis | N/A for command execution |
| F NATS/bus unavailable | bus is the PostgreSQL outbox; NATS is wake-up only | durable, recoverable, no fabricated completion |
| G adapter timeout | kernel::test_bus_times_out_into_reconciliation_not_success | reconciliation_required |
| H duplicate callback / I out-of-order | existing ingress ledger suites (unchanged) | idempotent / no rollback |
| J restart | integration::test_chaos_j_restart_… | operation/idempotency/timeline durable; retry is a replay; new worker completes |
| K two workers race | kernel + integration two_workers_one_effect | one lease, one effect |
| L stale lease | integration lease-expiry + fencing | bounded recovery; stale finalization refused |
| readback mismatch/unavailable/unsupported, reject, transient bound + dead-letter, kill switch at execution | kernel suite | as designed |
All effects synthetic (TEST_SYN fixture); provider_effects counted per fixture.
