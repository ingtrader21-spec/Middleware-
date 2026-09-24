from pathlib import Path


PRIVATE = Path("deploy/readiness/Caddyfile.private-vicidial-ingress")
PUBLIC = Path("deploy/readiness/Caddyfile.public-denial.snippet")
COMPOSE = Path("deploy/compose.runtime.yaml")


def test_private_listener_is_bound_to_server_a_and_requires_mtls():
    source = PRIVATE.read_text()
    compose = Path("deploy/readiness/compose.private-vicidial-ingress.yaml").read_text()
    assert '"10.40.0.1:443:443"' in compose
    assert '"65.109.65.169:443:443"' in compose
    assert "ports: !override" in compose
    assert "mode require_and_verify" in source
    assert "trust_pool file /run/secrets/middleware-private-ingress/client-ca.crt" in source
    assert "remote_ip 10.40.0.2" in source
    assert "respond 403" in source


def test_readiness_is_the_only_enabled_private_application_route():
    source = PRIVATE.read_text()
    assert "/api/v1/readiness/server-a/challenge" in source
    assert "max_size 4KB" in source
    assert "{http.request.tls.client.certificate_der_base64}" in source
    assert "header_up -X-Codestra-Verified-Source-IP" in source
    assert "header_up -X-Codestra-Client-Certificate-DER" in source


def test_event_ingress_is_configured_but_fail_closed():
    private = PRIVATE.read_text()
    compose = COMPOSE.read_text()
    assert "/api/v1/events/vicidial /api/v2/telephony/events" in private
    assert '{env.VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED} == "true"' in private
    assert 'VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED: "false"' in compose
    assert 'PUBLISHER_CANARY_ENABLED: "false"' in compose


def test_public_readiness_and_event_routes_are_denied():
    source = PUBLIC.read_text()
    assert "/api/v1/readiness/server-a/challenge" in source
    assert "/api/v1/events/vicidial /api/v2/telephony/events" in source
    assert source.count(" 404") == 2


def test_proxy_never_trusts_client_identity_headers():
    source = PRIVATE.read_text()
    assert source.count("header_up -X-Codestra-Verified-Source-IP") == 2
    assert source.count("header_up -X-Codestra-Client-Certificate-DER") == 2
    assert "X-Service-Identity" not in source
    assert "X-Codestra-Publisher-ID" not in source


def test_no_administrative_or_general_gateway_route_is_exposed():
    source = PRIVATE.read_text()
    for forbidden in ("/docs", "/openapi", "/metrics", "/dependencies", "handle_path /*"):
        assert forbidden not in source


def test_private_proxy_is_isolated_and_event_gate_stays_false():
    compose = Path("deploy/readiness/compose.private-vicidial-ingress.yaml").read_text()
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert 'VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED: "false"' in compose
    assert "networks: [middleware_edge]" in compose
    assert "codestra_backend" not in compose
