# Failure and recovery

Retry: timeout, reset, HTTP 429/502/503/504, and temporary dependency failure. Fail closed without blind retry: schema/tenant/auth/scope/contract errors, HTTP 400/401/403, payload conflict, and stale business version. Attempts are bounded and terminal failures retain append-only dead-letter and audit evidence.

Worker restart leaves the lease recoverable after expiry. Odoo restart leaves middleware result state pending/retry. Middleware restart leaves Odoo outbox and middleware result outbox durable. Recovery never deletes events and manual replay creates linked new processing evidence.
