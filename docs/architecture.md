# Middleware Phase 1 architecture

VICIdial sends a signed JSON event to the middleware. The API authenticates and validates the payload, enforces `TEST_SYN`, then inserts the event, its delivery rows, and its idempotency response in one PostgreSQL transaction before returning HTTP 202. Workers claim queued deliveries with `FOR UPDATE SKIP LOCKED`.

Odoo and n8n adapters are disabled in this phase. No network calls are made by the implementation or tests.
