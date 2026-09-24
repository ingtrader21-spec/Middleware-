# Operations runbook

1. Confirm all external-write flags are false.
2. Verify the mTLS/HMAC matrix.
3. Verify migrations in a restored disposable database.
4. Validate model listeners are loopback-only.
5. Install the worker artifact and unit without creating the activation marker.
6. Run synthetic tests with claims enabled only in isolation.
7. Monitor queue depth, oldest job, leases, retries, dead letters, authentication failures, quota denials, and heartbeat age.
8. Activation requires a separate protected approval.
