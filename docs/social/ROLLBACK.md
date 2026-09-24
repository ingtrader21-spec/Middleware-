# Rollback

No Phase 1 runtime deployment occurs. Code rollback is a normal commit revert. Before database rollback, confirm no later migration depends on `0033_social_publishing_foundation` and export required social audit evidence. Downgrade drops only the newly introduced social tables in reverse dependency order. It does not alter existing Postiz, n8n, Odoo, outbox or provider credentials.
