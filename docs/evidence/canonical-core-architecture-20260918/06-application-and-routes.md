# 06 — Single application factory and route registry

`app/application.py::create_app(settings=None, runtime=None, *, profile=AppProfile.CONTROL_PLANE,
legacy_monolith=False, service=None)` is the only `create_app` for Middleware processes
(`tests/test_architecture_governance.py::test_create_app_is_defined_once`; the two isolated services keep theirs).

| Profile | Process | Groups mounted | Unique operations | Route-table sha256 |
| --- | --- | --- | --- | --- |
| `INTEGRATION` | `python -m app.entrypoints.integration_api` (`deploy/compose.runtime.yaml`, :8095) | CANONICAL + COMMON + INTEGRATION | 272 | `c7e97c3f974fe5b789693fc12e097f9d26475b945568fc000c2938adc36574f9` |
| `CONTROL_PLANE` | `uvicorn app.main:create_app --factory` (production read-only canary) | CANONICAL + COMMON + APPOLON | 298 | `3ce99f40c0cd4f86a890d01641dcd5d61d3f2a03dafb466db90a0d650a219020` |
| `MONOLITH` | `app.main:app` (in-process; CI "Application startup" step) | all + MONOLITH + LEGACY_MONOLITH_ONLY | 515 | `cb9c88e56b6fcf70c48ee1737c88fd691a09fbedc02105ac935a4a4929574422` |

Hashes are sha256 of the JSON-sorted `(method, path)` list built with test settings; regenerate with the
figures script in the PR description.

## Registry groups (`app/router_registry.py`)

| Group | Size | Members |
| --- | --- | --- |
| `CANONICAL_ROUTERS` | 17 | automation v2, automation, callbacks, email production, agent provisioning (+reads), session context, calls, activity, presence, queues, tenants, campaigns, monitoring, observability sync, integrations, Odoo event ingress |
| `COMMON_ROUTERS` | 3 | campaign design, Klyrow events, Telnexa events |
| `INTEGRATION_ROUTERS` | 18 | commands, control, reports, operations, lead reconciliation, lead automation, orchestration, provider webhooks, mappings, webphone, n8n staging/transport/runtime, quarantine, telephony, sales, booking, platform |
| `APPOLON_ROUTERS` | 7 | operations dashboard, Appolon operations, control API, compatibility API, domain API, webhook API, `appolon_routes.router` |
| `MONOLITH_ROUTERS` | 19 | HMAC VICIdial events, legacy control events, publisher canary, agent realtime, n8n target, internal AI jobs, Klyrow mail, AI console, TTS, AI commands, orders, AI, provider commands, Postiz, campaign search, registry, recordings (+service identity), social |
| `LEGACY_MONOLITH_ONLY_ROUTERS` | 2 | `n8n_control_plane.router`, `domain_api.legacy_n8n_router` (edge-denied aliases) |

`assert_unique_routes(app)` walks the route tree (including lazily included routers) and raises
`DuplicateRouteError` for any repeated `(method, path)`; `create_app` calls it for every profile.

## Duplicates resolved (were shadowed silently before)

| Operation | Before | After |
| --- | --- | --- |
| `POST /api/v1/events/vicidial` | HMAC ingress + dead `control.event` alias | HMAC ingress only |
| `POST /api/v1/events/odoo` | `control.event` + dead `lead_automation.receive_odoo_event` | `control.legacy_events_router` (monolith only); the lead-automation registration removed |
| `POST /v1/telephony/calls/originate` | Appolon calling contract (canary) and ORM agent-UI handler (monolith/integration) | Appolon calling contract (documented in `docs/ODOO-CALLING-ENDPOINTS.md`); ORM handler unrouted |

## Contract parity (computed)

- Integration profile: every `shared_edge` row of `deploy/public-api-route-contract.json` (v2, 92 rows, pinned
  `7580123d…`) is mounted; **no** `denied` row is mounted (`scripts/audit_release_endpoints.py` passes).
- Control-plane profile: every `shared_edge` row mounted; no `denied` row mounted (the five deprecated n8n
  aliases moved to the monolith).
- Monolith: mounts exactly the documented deprecated aliases (`tests/test_public_api_route_contract.py`).
- Generated control-plane contract (`contracts/platform/*`, `config/api-completion-matrix.yaml`) regenerated
  with `scripts/generate_api_contracts.py` (290 OpenAPI routes) and verified with `--check`.

Tests: `tests/test_architecture_governance.py::test_every_profile_is_unique_and_nested_in_the_monolith`,
`::test_routers_are_mounted_only_through_the_registry`, `::test_fastapi_is_constructed_only_by_approved_modules`,
`tests/test_route_table_uniqueness.py` (3), `tests/test_public_api_route_contract.py` (13),
`tests/test_release_endpoint_audit.py`, `tests/test_generated_api_parity.py` (3), `tests/test_entrypoints.py`
(narrow surfaces unchanged: `/api/v1/events/vicidial` still absent from the integration API).
