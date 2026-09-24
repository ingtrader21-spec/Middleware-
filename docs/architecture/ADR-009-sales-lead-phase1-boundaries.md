# ADR-009: Phase 1 sales lead authority boundaries

Status: Accepted for development and staging

## Decision

The Phase 1 flow is:

```text
self-hosted scraper
  -> authenticated middleware lead intake
  -> strict validation and deterministic identity resolution
  -> bounded, tenant-scoped Odoo read-only comparison
  -> deterministic DNC, suppression and consent evaluation
  -> persisted dry-run result or duplicate-review record
```

Odoo 19 remains the authoritative CRM and business record. Middleware is the
only cross-system operational gateway. n8n may orchestrate asynchronously but
is not authoritative. The scraper cannot write to Odoo, n8n or VICIdial. No
component may access VICIdial database tables directly.

All Phase 1 Odoo operations are read-only. Verification is always dry-run;
Odoo writes, VICIdial publication, email, SMS, calling and other outreach are
separately gated and default off. AI output is non-authoritative and cannot
decide identity, consent, DNC, suppression, eligibility or outreach.

Every decision is tenant- and campaign-bound, uses stable reason codes and a
versioned policy, and produces an append-only redacted audit record. An
unavailable authoritative dependency never causes a `NET_NEW` decision.

## Consequences

Potential duplicates require human review and never merge automatically.
Provider data and source-provided consent are evidence only. Production
activation, paid provider calls and scraper deployment are outside this ADR.
