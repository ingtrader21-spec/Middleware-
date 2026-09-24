# 13 — Test and validation results (local, development host)

Host: Windows 10, Python 3.12, no PostgreSQL/Redis/Docker available (Docker-, Alembic-chain-, NATS-, Temporal-
and readiness-matrix proofs run only in CI; see 15). Every command below was executed on the final tree.

## Full regression (`python -m pytest tests -q`)

| Tree | Result |
| --- | --- |
| Base `8995859` | 118 failed, 3036 passed, 252 skipped |
| Mission 2 final | 118 failed, **3093 passed**, 252 skipped |
| Failure-set difference | **none** — the identical 118 tests fail on both trees, all host-environmental (POSIX file mode 0600 checks, `os.geteuid`, symlink privilege `WinError 1314`, `O_NOFOLLOW`): `test_vicidial_mtls_client` 33, `test_vicidial_internal_call_adapter` 23, `test_elevenlabs_tts_policy` 10, `test_qwen_auth_verifier` 6, `test_controller_api` 4, `test_readiness_challenge` 4, `test_qwen_polling_worker` 3, `test_runtime_sql_history_lock` 2, `test_server_a_agent` 2, `test_provisioning_service_adapter` 2, `test_openai_provider_policy` 2, and 11 single tests |
| New tests | +57 passing: `test_architecture_governance.py` (17), `test_core_runtime_container.py` (13), `test_core_config_authority.py` (11), rewritten `test_integration_manifest_health.py` (25 cases), `test_route_table_uniqueness.py::test_registry_refuses_duplicate_registrations`, `test_security.py` JetStream cases, `test_integration_runtime_wiring.py` startup-failure case, `test_entrypoints.py` narrow-service readiness case |

Targeted suites re-run green after every change set: `test_security`, `test_runtime`, `test_entrypoints`,
`test_integration_manifest_health`, `test_integration_api_entrypoint_routes` (38), `test_odoo_campaign_adapter_routes`,
`test_public_api_route_contract`, `test_release_endpoint_audit`, `test_route_table_uniqueness`, `test_generated_api_parity`,
`test_n8n_security_invariants`, `test_platform_control_plane`, `test_operation_domain_api_validation`, `test_full_api_routes`,
`test_observability`, `test_lead_intake_api`, `test_sales_api`, `test_booking_api`, `test_provider_webhooks`, `test_webphone`,
`test_campaign_design`, `test_certify_edge_integration`, `test_staging_intake_observability_contract_validation` (69),
`recording/test_api_contract`, `test_auth`.

## Lint and types (CI rules)

| Command | Result |
| --- | --- |
| `ruff check --select E9,F63,F7,F82 app tests` | All checks passed |
| `ruff check <106 changed Python files>` (full default ruleset, as CI applies to changed files) | All checks passed |
| `mypy --platform linux --ignore-missing-imports --explicit-package-bases <106 changed Python files>` | Success: no issues found in 106 source files |
| `python -m compileall -q app` | ok |

## Repository validators (as run by `scripts/run_ci.sh` / `scripts/project_ci.sh`)

`validate_repository_governance` PASS · `validate_automation_contract_conformance` PASS (13) ·
`validate_automation_operation_policy` PASS · `validate_repository` PASS (1869 files) ·
`validate_middleware_authority_convergence` PASS · `validate_middleware_authority_assets` PASS ·
`validate_workstream_manifest` PASS · `validate_connectivity_contracts` PASS · `validate_identity_webhook_contracts` PASS ·
`validate_moneybee_account_events` PASS · `validate_n8n_flow` PASS · `validate_provider_operation_policy` PASS (+ unittest OK) ·
`validate_site_workstreams` PASS · `validate_site_routes_and_leads` PASS · `validate_intake_observability` **PASS (re-targeted)** ·
`validate_observability_alert_contract` PASS · `validate_codestra_manifest` PASS ·
`validate_platform_control_plane` **PASS (was failing on the base)** · `validate_calling_contract_pin` PASS (+ self-test) ·
`validate_staging_intake_observability_contract` **PASS (re-targeted; `-O` mode covered by its test)** ·
`generate_api_contracts.py --check` PASS (290 OpenAPI routes) · `audit_release_endpoints` (source mode, via its test) PASS.

## Not executed locally (CI-only)

Docker test/runtime image builds, `alembic upgrade head` chain + downgrade/re-upgrade + `pg_dump`/`pg_restore`
round-trip, `scripts.migrate_runtime` (+ `--verify-only`), disposable PostgreSQL/Redis/NATS/Temporal
integrations, the synthetic no-effect acceptance E2E, and the readiness failure-mode matrix against a live
`uvicorn`. The mapping of every matrix case to the canonical code path is in 08; nothing here claims those
proofs ran.
