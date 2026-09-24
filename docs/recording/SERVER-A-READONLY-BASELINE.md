# Server A read-only baseline

Observed 2026-07-31 on host `middleware` (`10.40.0.1`). No runtime changes were
made.

| Item | Current state |
|---|---|
| Middleware | `codestra-middleware-1`, healthy; deployed image `codestra/middleware:webphone-keycloak-staging-20260726`; source `/opt/codestra/middleware` at `cbc9e54c7f5a817cc526a87bac7510870a2f5dce`, dirty and not image-bound |
| Odoo | healthy; Odoo 19.0-20260630; separate recording module absent, incompatible legacy model present |
| n8n | healthy; related recording/QA workflows present but inactive; target generic workflow absent |
| Object storage | absent |
| Retention worker | absent |
| PostgreSQL | healthy |
| Redis | healthy |
| Caddy | healthy |
| Keycloak | healthy |

The deployed dirty Middleware checkout was not used as this branch base.
