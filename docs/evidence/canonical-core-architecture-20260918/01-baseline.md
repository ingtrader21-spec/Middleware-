# 01 — Baseline (base commit `8995859`)

Measured on the base before any Mission-2 change (see
`docs/architecture/canonical-core-migration.md` § CURRENT_ARCHITECTURE for the full table).

| Concern | Count on base | Detail |
| --- | --- | --- |
| Configuration authorities | 2 | `app/config.py` (frozen dataclass `Settings`, 38 importers) and `app/core/config.py` (pydantic `Settings`, 141 importers) |
| Runtime authorities | 3 | `app/runtime.py` `Runtime`/`build_runtime`, `app/entrypoints/runtime.py` `add_api_runtime`, `app/appolon_factory.py` lifespan |
| asyncpg pools opened by the primary runtime | 5 | inbox, commands, automation, realtime, communications (`*.connect()` each) |
| SQLAlchemy engines | 1 | `app/db/session.py` import-time global |
| Request guards | 3 | `app.main.control_request_guard`, `entrypoints.runtime.request_controls`, Appolon `observe_request` |
| Health/readiness/version implementations | 3 | `app.main`, `entrypoints.runtime.add_api_runtime`, `appolon_factory` inline |
| FastAPI factories for the primary service | 3 | `app.main:app` (367 routes), `app.entrypoints.integration_api:app` (275), `app.main:create_app` = Appolon (canary) |
| Duplicate `(method, path)` registrations on the monolith | 2 | `POST /api/v1/events/odoo`, `POST /api/v1/events/vicidial` (pinned by `tests/test_route_table_uniqueness.py`) |
| Migration head | `0066_reconcile_odoo_campaign_scope` | 80 revisions, digest `sha256:b2270941…` |
| Edge route contract | v2, 92 rows | pinned `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5` |

Local full test run of the base on the Windows development host: **115 failures / 3036 passed / 252 skipped**;
all 115 are host-environmental (POSIX file-mode / symlink / uid checks). This is the comparison baseline for 13.

Pre-existing CI state of the base PR #278 (from GitHub): `Required exact-SHA CI` **success**; `Middleware CI`
`validate` **failure** (`Validate middleware source head`, `Validate middleware merge result`,
`connector-runtime-build`, `container-security`), `Production orchestrator contract` **failure**,
`Trusted production orchestrator evidence` **failure**, `beyvra-email-authority` **failure**. The
source-head validation failure includes `scripts/validate_platform_control_plane.py`, which had drifted when
commit `ad8b2f9` moved the n8n compatibility router behind the router registry; Mission 2 re-targets that
validator (see 11).
