# Phase 2 controlled staging

Phase 2 extends the provider-neutral foundation with a PostgreSQL repository, persistent idempotency, job leases, Redis signaling, a single-concurrency worker, persistent webhook receipts, and IntegrationEvent creation. Source defaults remain off and no production service is deployed.

Middleware Server A is `65.109.65.169`. Postly Server C is `49.12.145.107`, with verified VLAN peers `10.40.0.1` and `10.40.0.3`. Private ICMP with the configured MTU and TCP/TLS reachability passed without changing the public route. The deployed Postiz runtime lacks an approved staging machine credential, staging-safe account, and signed outward webhook contract, so authenticated API/account/webhook tests remain externally blocked. Local disposable PostgreSQL and Redis tests validate durable behavior without provider side effects.

Before staging activation, provision approved access, confirm a `STAGING_SAFE` account, install secrets as files, enable only isolated staging overrides, and rerun the acceptance matrix. `SOCIAL_PUBLISH_ENABLED` and all Odoo write flags remain false.
