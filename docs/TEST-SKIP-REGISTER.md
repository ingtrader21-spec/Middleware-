# Test skip register

Baseline observed on `main` at `3f95d771667b2a5e29f9cbd589d8309f2201bdd7`:
**503 passed, 45 skipped**.

The counts are the unit-suite result reported by the `Validate middleware source
head`, `Validate middleware merge result` and `docker-test-build` jobs of
`Middleware CI`. Refresh this baseline and
`config/test-skip-register.v1.json` in the same change whenever those counts
move.

The skipped tests are not accepted as unowned coverage gaps. They are
infrastructure-gated tests executed by dedicated CI jobs with disposable
dependencies.

| Marker / dependency | Unit-suite behavior | Authoritative CI execution |
|---|---|---|
| `RUNTIME_INTEGRATION_TESTS=1` with PostgreSQL and Redis | runtime, incident, and synthetic tests are skipped without disposable URLs | `Disposable PostgreSQL Redis integration` and `Synthetic no-effect acceptance E2E` |
| `NATS_INTEGRATION_TESTS=1` with disposable JetStream | skipped without isolated NATS | `Disposable NATS JetStream integration` |
| Temporal test server | skipped without isolated Temporal | `Temporal critical workflow integration` |
| Connector-runtime PostgreSQL contract | skipped without connector test database | `Connector storage v1` |

Rules:

1. Every `skip`, `skipif`, or environment-gated integration module must appear
   in `config/test-skip-register.v1.json` and have an always-on dedicated job.
2. A new skipped test without a register entry fails governance validation.
3. A dedicated integration job may not use shared staging or production data.
4. The general unit result is not release evidence by itself; every dedicated
   job is a required check on `main`.
5. Permanent skips and `xfail` without a W-code, owner, and expiry are forbidden.

W0 closes the unknown-coverage finding by making every reason and execution path
explicit. W2-W7 remove any skip whose dependency can be supplied cheaply in the
primary test target.
