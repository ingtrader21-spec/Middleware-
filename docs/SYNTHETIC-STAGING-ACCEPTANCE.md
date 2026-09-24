# Synthetic staging acceptance

Production promotion requires two different proofs. Neither proof may be
substituted for the other.

## 1. Combined disposable E2E gate

The `Synthetic no-effect acceptance E2E` job in Middleware CI runs
`scripts/synthetic_acceptance_ci.sh` with disposable PostgreSQL, Redis, NATS
JetStream, and Temporal test infrastructure. One signed canonical event must
complete this journey:

```text
FastAPI authentication and HMAC verification
  -> Redis in-flight replay guard
  -> PostgreSQL inbox + immutable ledger + transactional outbox
  -> leased outbox worker
  -> isolated JetStream acknowledgement and consumer delivery
  -> Temporal reconciliation workflow
  -> idempotent API retry
```

The test asserts one inbox row, one immutable-ledger entry, one outbox row, one
JetStream message, a completed audited outbox delivery, one completed Temporal
workflow, and zero provider command rows. It uses only `middleware_test_*`
PostgreSQL databases, a nonzero local Redis database, the
`CODESTRA_TEST_EVENTS` stream, and a localhost NATS server pinned by digest.

Make this exact job name a required protected-branch check. The release workflow
already runs only after the complete `Middleware CI` workflow succeeds.

## 2. Deployed staging acceptance

The running service exposes `GET /v1/runtime/safety` only to the
`monitoring-readonly` identity with `health.read`. The response contains the
effective immutable settings object projected into a non-secret schema; it does
not return connection strings, credential paths, tokens, webhook secrets, or a
production activation identifier.

After deploying an image digest to staging, run:

```bash
STAGING_BASE_URL=https://middleware-staging.example.invalid \
STAGING_MONITORING_TOKEN='<short-lived monitoring token>' \
STAGING_ODOO_PRODUCER_TOKEN='<short-lived staging producer token>' \
STAGING_ODOO_WEBHOOK_SECRET='<staging-only webhook secret>' \
STAGING_SYNTHETIC_TENANT_ID='<isolated staging tenant>' \
EXPECTED_SOURCE_SHA='<approved 40-character merge SHA>' \
EXPECTED_IMAGE_DIGEST='sha256:<approved image digest>' \
python3 scripts/staging_synthetic_acceptance.py
```

Supply these values through the deployment platform's protected staging
environment. Do not write them to an environment file, workflow artifact, test
report, or repository setting visible to untrusted pull requests. The script
does not follow redirects and never prints secrets or the tenant identifier.

The script fails closed unless all of the following are true before it submits
an event:

- the environment and runtime profile are exactly staging;
- source SHA, image digest, and migration head match the approved release;
- PostgreSQL, Redis, the command ledger, and Keycloak readiness checks pass;
- in-memory persistence, NATS dispatch, the outbox worker, and the Temporal
  worker are disabled in the deployed staging profile;
- every declared external-effect flag is false;
- production dialing is disabled and no production activation is configured.

It then records one deliberately non-customer synthetic event in the immutable
staging ledger and immediately retries the identical signed request. The first
request must return canonical `202 accepted`; the retry must return canonical
`200 duplicate`. Because effective dispatch was proven disabled first, the
probe cannot leave the middleware outbox for NATS or reach a provider. Retain
the synthetic ledger row as acceptance evidence; do not delete or rewrite it.

The repository intentionally does not invent a staging hostname, token, tenant,
or runner. The central deployment pipeline that owns the release manifest must
provide those values and archive the script's non-secret JSON result against the
exact image digest before production approval.
