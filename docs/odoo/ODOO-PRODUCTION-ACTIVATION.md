# Production activation

This mission does not authorize production activation. A separate approval must certify staging round trips, recovery, load, tenant isolation, security scans, observability, rollback rehearsal, and credential ownership. Production additionally requires both `ODOO_PRODUCTION_WRITES_ENABLED=true` and `LIVE_WRITES_ENABLED=true`, an approved tenant/result allowlist, and monitored change window. Defaults and current runtime values remain false.
