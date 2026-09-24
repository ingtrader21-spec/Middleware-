# 04 — Startup validation: `app/core/bootstrap.py`

| Function | Caller | Does |
| --- | --- | --- |
| `validate_configuration(settings=None)` | `app.application.create_app` (with the process-wide `settings`), tests | `Settings.from_env()` when none given; otherwise re-runs `validate_domain()` + `validate_safety()`; then `_assert_identity_invariants`: https issuer unless synthetic, audience `middleware-api`, JWKS present, synthetic identity never in staging/production, issuer equals the environment authority, https JWKS in staging/production, RS256 + 300 s token policy. Raises `StartupError`. |
| `validate_startup(service, settings=None, queue=None, environ=None)` | `app.entrypoints.runtime.run_api` / `run_worker` (via `validate_runtime`) | `validate_configuration` + per-service process requirements (`SERVICE_NAME`/`QUEUE_NAME` identity; event gateway needs `auth_ready` + quarantine secrets; integration API / policy engine / canonical API need `middleware_secret`; integration API and canonical API need the three quarantine secrets; schema head) + `codestra_feature_flag_state` gauges. Returns `StartupReport` whose `summary` never contains secret values. |

Behaviour change: every process now runs the full canonical validation (`validate_domain` + `validate_safety`
+ identity invariants) at start, where the former `validate_runtime()` ran `validate_safety()` only. Every
deployed profile (`config/environments/*.env.example`, `deploy/compose.runtime.yaml`, canary compose) already
satisfies `validate_domain()` because the deployed integration API executed it in its lifespan before Mission 2.

The `FEATURE_FLAG_STATE` gauge moved from `app/entrypoints/runtime.py` to `bootstrap` (single registration in
the Prometheus registry; the entrypoint re-exports it).

Tests: `tests/test_core_config_authority.py::test_startup_validation_requires_the_service_secrets`,
`::test_startup_reports_flags_without_secrets`,
`tests/test_architecture_governance.py::test_bootstrap_rejects_implicit_https_downgrade`.
