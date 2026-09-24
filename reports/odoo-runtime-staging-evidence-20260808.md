# Odoo runtime staging evidence — 2026-08-08

## Proven

- Existing confidential client `codestra-middleware-staging` restored from its
  approved secret-file mount; no duplicate identity or embedded secret added.
- RS256 signature, issuer, audience, five-minute expiry, runtime scopes, business
  unit scope, and synthetic campaign scope validated.
- Authenticated `/health/ready` and capabilities returned HTTP 200; invalid JWT
  returned HTTP 401.
- `TEST_SYN_ODOO_RUNTIME_CANARY_20260808` was created through Odoo ORM and its
  transactional outbox.
- Middleware claimed one leased event, verified its payload hash, committed one
  durable intake plus audit, and ACKed only after commit.
- Middleware queued one durable normalized result, delivered it with OAuth2 to
  Odoo, and Odoo completed the originating outbox.
- Identical result replay retained one logical Odoo result inbox mutation.
- Locked container suite: 851 passed, 20 skipped. The mandatory PostgreSQL n8n →
  durable result → Odoo adapter integration test separately passed on a migrated
  rehearsal database.
- Ruff, Mypy, pip-audit, branch-diff Gitleaks, and Trivy HIGH/CRITICAL passed.
  Full-history Gitleaks reports 11 pre-existing findings. Bandit reports three
  pre-existing medium findings outside the changed Odoo runtime files.
- Persisted staging, production, and live write switches are false/default closed.

## Not certified

- The Odoo addon lacks the mission's full approved read service surface and the
  full allowlisted business-domain result handlers.
- Restart recovery, bounded 25-flow load, tenant-A/tenant-B isolation, compliance
  precedence, and p50/p95/p99 measurements were not completed against the final
  committed/deployed image.
- The tested internal service route uses a private Docker network HTTP endpoint;
  end-to-end TLS hostname/CA validation for worker-to-Odoo traffic remains open.
- The exact final commit image was not deployed as a persistent staging worker;
  canaries ran in isolated one-shot candidate containers.

Therefore this evidence proves the authenticated core transport round trip but
does not support full production-grade staging certification.
