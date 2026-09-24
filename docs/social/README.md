# Codestra Social API

This package is the provider-neutral control plane for social accounts, campaigns, posts, media, jobs, webhooks, analytics and audit evidence. It wraps Postly/Postiz first while preserving an activation path for Hootsuite and future adapters.

All write paths are disabled by default. Start with `ARCHITECTURE.md`, then use `OPERATIONS.md` for safe validation.

Production canary preparation is documented in `PHASE4_PRODUCTION_READINESS.md`. It adds source-level safety controls only; `PHASE4_ACCEPTANCE.md` records the unresolved external gates that prohibit a live canary.
