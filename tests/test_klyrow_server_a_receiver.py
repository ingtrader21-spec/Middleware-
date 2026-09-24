from pathlib import Path

COMPOSE = Path("deploy/klyrow/compose.server-a-receiver.yaml")
SOURCE = COMPOSE.read_text()


def test_server_a_receiver_is_loopback_only_and_targets_integration_api() -> None:
    assert "middleware-integration-api:" in SOURCE
    assert 'KLYROW_MAIL_INGRESS_ENABLED: "true"' in SOURCE
    assert "name: klyrow-receiver" in SOURCE
    assert "target: 8095" in SOURCE
    assert 'published: "18181"' in SOURCE
    assert "host_ip: 127.0.0.1" in SOURCE
    assert "protocol: tcp" in SOURCE


def test_receiver_override_contains_no_secret_values() -> None:
    source = SOURCE.lower()
    assert "hmac_secret" not in source
    assert "password" not in source
    assert "0.0.0.0" not in source


def test_odoo_delivery_is_owned_and_configured_by_middleware_worker() -> None:
    assert "middleware-klyrow-mail-odoo-worker:" in SOURCE
    assert 'KLYROW_MAIL_ODOO_DELIVERY_ENABLED: "true"' in SOURCE
    assert "KLYROW_MAIL_ODOO_DATABASE: codestra_odoo" in SOURCE
    assert (
        "KLYROW_MAIL_ODOO_USERNAME: codestra.middleware@service.internal"
        in SOURCE
    )
