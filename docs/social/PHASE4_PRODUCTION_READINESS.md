# Phase 4 production readiness

Phase 4 adds production canary controls but does not activate production publishing. Phase 2 exact-SHA CI passed, while authenticated staging acceptance remains incomplete. Phase 3 has no certified Hootsuite implementation. Therefore Postly is the only possible future canary provider, and live canary execution remains blocked.

Production requests require every global, provider, canary, backup, rollback, webhook, monitoring, SQL-worker, allowlist, RBAC, account-health, classification, content-approval, and idempotency gate. A missing or malformed gate denies the request before a publish job is created. The worker repeats mutable account and policy checks immediately before dispatch.

Automatic failover and dual publishing are prohibited. PostgreSQL remains authoritative. Redis loss cannot erase intent. Odoo production writes remain disabled.
