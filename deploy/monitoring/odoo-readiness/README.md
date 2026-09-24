# Odoo production monitoring readiness

This profile adds pinned PostgreSQL, Redis, and cAdvisor exporters and explicit
Odoo/Caddy blackbox targets. Credentials are supplied only through root-owned
Docker secrets at deployment time; no values belong in this repository.

Required deployment checks: `docker compose config`, `promtool check config`,
`promtool check rules`, target health, Alertmanager route validation, and an
internal-only readiness test alert. Do not activate during the Odoo upgrade
window without the recorded authorization and rollback assets.
