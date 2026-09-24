from pathlib import Path
import re


COMPOSE = (
    Path(__file__).resolve().parents[1] / "deploy" / "compose.runtime.yaml"
).read_text(encoding="utf-8")
TELEPHONY_COMMAND_WORKER = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "compose.telephony-command-worker.yaml.example"
).read_text(encoding="utf-8")
RUNTIME_DOCKERFILE = (
    Path(__file__).resolve().parents[1] / "Dockerfile.runtime"
).read_text(encoding="utf-8")


def _service_block(service_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(service_name)}:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)",
        COMPOSE,
    )
    assert match is not None, f"missing runtime service: {service_name}"
    return match.group("body")


def test_separated_runtime_catalog_has_required_specialized_services() -> None:
    expected_commands = {
        "middleware-extension-allocator": "app.entrypoints.extension_allocator",
        "middleware-telephony-provisioning": "app.entrypoints.telephony_provisioning",
        "middleware-vicidial-adapter": "app.entrypoints.vicidial_adapter",
        "middleware-pjsip-adapter": "app.entrypoints.pjsip_adapter",
        "middleware-webphone-session-issuer": "app.entrypoints.webphone_session_issuer",
    }

    for service_name, entrypoint in expected_commands.items():
        block = _service_block(service_name)
        assert f"command: [python, -m, {entrypoint}]" in block
        assert "<<: *" in block


def test_specialized_services_use_distinct_secret_references() -> None:
    expected_secrets = {
        "middleware-extension-allocator": "middleware-extension-allocator-database-url",
        "middleware-telephony-provisioning": "middleware-telephony-provisioning-database-url",
        "middleware-vicidial-adapter": "middleware-vicidial-adapter-database-url",
        "middleware-pjsip-adapter": "middleware-pjsip-adapter-database-url",
        "middleware-webphone-session-issuer": "middleware-webphone-session-issuer-database-url",
    }

    for service_name, secret_name in expected_secrets.items():
        block = _service_block(service_name)
        assert f"/{secret_name}:/run/secrets/database_url:ro" in block


def test_runtime_action_flags_default_fail_closed() -> None:
    false_flags = (
        "LIVE_WRITES_ENABLED",
        "ODOO_WRITE_ENABLED",
        "CALLBACK_DISPATCH_ENABLED",
        "SEND_EVENTS",
        "BROAD_EVENT_DELIVERY_ENABLED",
        "ENABLE_EXTERNAL_DELIVERY",
        "VICIDIAL_WRITES_ENABLED",
        "PRODUCTION_CALLBACKS_ENABLED",
        "TRANSFERS_ENABLED",
        "PRODUCTION_WEBRTC_ENABLED",
        "PRODUCTION_N8N_ENABLED",
        "ALLOW_LIVE_EMAIL",
        "ALLOW_LIVE_SMS",
        "ALLOW_CAMPAIGN_ACTIVATION",
    )

    for flag in false_flags:
        assert f'{flag}: "false"' in COMPOSE


def test_default_runtime_is_the_canonical_integration_api_on_8095() -> None:
    runtime_stage = RUNTIME_DOCKERFILE.split("FROM runtime-common AS runtime", 1)[1].split(
        "FROM runtime-common AS worker", 1
    )[0]
    assert "EXPOSE 8095" in runtime_stage
    assert "127.0.0.1:8095/health" in runtime_stage
    assert "app.entrypoints.integration_api:app" in runtime_stage
    assert '"--port", "8095"' in runtime_stage
    assert "8080" not in runtime_stage


def test_production_odoo_route_uses_canonical_governed_api_and_private_ca() -> None:
    assert (
        "https://odoo.internal.codestra.agency/api/v1/integration/results"
        in COMPOSE
    )
    assert "/codestra/integration/v1/results" not in COMPOSE
    assert "ODOO_RESULTS_CA_FILE: /run/secrets/internal_integration_ca" in COMPOSE
    assert (
        "/etc/codestra/pki/internal-integration/ca.crt:"
        "/run/secrets/internal_integration_ca:ro"
    ) in COMPOSE


def test_canonical_compose_does_not_pin_one_off_scheduler_release() -> None:
    scheduler = _service_block("middleware-scheduler")
    assert "\n    image:" not in scheduler


def test_telephony_command_worker_template_is_source_only_and_fail_closed() -> None:
    assert "compose.telephony-command-worker.yaml.example" not in COMPOSE
    assert "app.entrypoints.telephony_command_worker" in TELEPHONY_COMMAND_WORKER
    assert 'TELEPHONY_COMMAND_WORKER_ENABLED: "false"' in TELEPHONY_COMMAND_WORKER
    assert (
        "TELEPHONY_CREDENTIAL_DIRECTORY: /run/secrets/middleware-telephony-client"
        in TELEPHONY_COMMAND_WORKER
    )
    assert "profiles: [telephony-command-worker]" in TELEPHONY_COMMAND_WORKER
    assert "middleware-telephony-command-worker-database-url" in (
        TELEPHONY_COMMAND_WORKER
    )
    assert "middleware-telephony-client:ro" in TELEPHONY_COMMAND_WORKER
