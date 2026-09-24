# Mission 2 evidence — canonical core architecture (2026-09-18)

Branch `mission/middleware-canonical-core-20260918`, stacked on PR #278 base
`899585932c51fdb02827c8e28777d388fbb43c44` (Mission-1 certified). Nothing in this
package was produced by running against a live environment; every figure comes
from source, local test execution on the development host, or GitHub CI metadata.

| # | File | Content |
| --- | --- | --- |
| 01 | [01-baseline.md](01-baseline.md) | State of the base commit: two settings lineages, three factories, five pools |
| 02 | [02-inventory.md](02-inventory.md) | Consumer inventory and every explicit migration performed |
| 03 | [03-config-authority.md](03-config-authority.md) | The single `Settings`, aliases, merged rules, config test matrix |
| 04 | [04-startup-validation.md](04-startup-validation.md) | `app/core/bootstrap.py` |
| 05 | [05-runtime-container.md](05-runtime-container.md) | `RuntimeContainer`: ownership, readiness, close, rebuild |
| 06 | [06-application-and-routes.md](06-application-and-routes.md) | Single factory, profiles, registry groups, route parity, duplicates |
| 07 | [07-identity.md](07-identity.md) | `IdentitySettings`, both verifiers, 401/403, environment pins |
| 08 | [08-health-readiness.md](08-health-readiness.md) | Health contract, CI failure-mode mapping, recovery |
| 09 | [09-db-authority.md](09-db-authority.md) | Alembic + runtime SQL authority and the `alembic_head` probe |
| 10 | [10-request-guard.md](10-request-guard.md) | The single guard and its behaviour changes |
| 11 | [11-legacy-removal.md](11-legacy-removal.md) | Shims, deletions, unrouted handlers, source-contract validators |
| 12 | [12-governance-tests.md](12-governance-tests.md) | What each governance test forbids |
| 13 | [13-test-results.md](13-test-results.md) | Local regression, baseline comparison, lint, type, validators |
| 14 | [14-review-findings.md](14-review-findings.md) | Self-review findings, resolutions, residual risks |
| 15 | [15-ci-and-pr.md](15-ci-and-pr.md) | Commit, push/PR status, exact-SHA CI plan, inherited reds |

Hard invariants (unchanged, all verified by tests named in 12/13): every
provider-effect capability disabled; synthetic CI identity never valid in
staging/production; no production deployment, live call/SMS/email/publication,
external write, secret creation, hardcoded credential or CI bypass.
