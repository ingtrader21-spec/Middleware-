from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "qwen-auth-verifier"
IMAGE = (
    "ghcr.io/codestra-srl/qwen-auth-verifier@sha256:"
    "cc7e2457fdd69fdd1bf766831f8f86396495b47e377e86b2d9df1d4fb5432390"
)


def load_text(name: str) -> str:
    return (DEPLOY / name).read_text()


def test_production_image_is_exact_and_runtime_is_hardened():
    text = load_text("compose.production.yaml")
    assert f"image: {IMAGE}" in text
    assert 'user: "10001:10001"' in text
    assert "restart: unless-stopped" in text
    assert "read_only: true" in text
    assert "cap_drop: [ALL]" in text
    assert "no-new-privileges:true" in text
    assert "ports:" not in text


def test_only_dedicated_proxy_network_is_trusted():
    verifier = load_text("compose.production.yaml")
    overlay = load_text("compose.reverse-proxy-network.overlay.yaml")
    assert "QWEN_TRUSTED_PROXY_CIDR: 10.250.241.2/32" in verifier
    assert "ipv4_address: 10.250.241.3" in verifier
    assert "ipv4_address: 10.250.241.2" in overlay
    for text in (verifier, overlay):
        assert "external: true" in text
        assert "name: codestra_qwen_auth_private" in text


def test_secret_is_file_mounted_and_never_in_environment():
    text = load_text("compose.production.yaml")
    assert "QWEN_HMAC_SECRET_FILE: /run/secrets/qwen-hmac" in text
    assert "QWEN_HMAC_SECRET:" not in text
    assert "/run/codestra/qwen-auth-verifier-secrets/qwen-hmac:/run/secrets/qwen-hmac:ro" in text
    assert "/run/codestra/qwen-auth-verifier-secrets/client-ca.crt:/run/secrets/client-ca.crt:ro" in text
    assert "/etc/codestra/secrets" not in text
    assert "/etc/codestra/pki" not in text


def test_certificate_serial_uses_exact_x509_integer_value():
    compose = load_text("compose.production.yaml")
    runbook = load_text("PRODUCTION_DEPLOYMENT.md")
    assert 'QWEN_CERTIFICATE_SERIAL: "507396079750943841071109526780094961193782398461"' in compose
    assert 'QWEN_CERTIFICATE_SERIAL: "3001"' not in compose
    assert "58E06D577107AD0B753B7098B9131B797548CDFD" in runbook
    assert "507396079750943841071109526780094961193782398461" in runbook


def test_projection_is_tmpfs_only_exact_and_permission_strict():
    prepare = load_text("prepare-runtime-secrets")
    cleanup = load_text("cleanup-runtime-secrets")
    assert "findmnt -n -o FSTYPE /run" in prepare
    assert "root:root:600" in prepare
    assert "install -d -o 10001 -g 10001 -m 0700" in prepare
    assert prepare.count("install -o 10001 -g 10001 -m 0600") == 2
    assert "cmp -s" in prepare
    assert "qwen-hmac client-ca.crt" in prepare
    assert "unlink" in prepare and "unlink" in cleanup
    assert "rmdir" in cleanup
    assert "rm -rf" not in prepare + cleanup
    assert "cat " not in prepare + cleanup


def test_replay_init_is_bounded_deterministic_and_networkless():
    text = load_text("initialize-replay-volume")
    assert "--rm --network none" in text
    assert "--cap-drop ALL" in text
    assert "--cap-add CHOWN --cap-add FOWNER" in text
    assert "--entrypoint python" in text
    assert "@sha256:cc7e2457fdd69fdd1bf766831f8f86396495b47e377e86b2d9df1d4fb5432390" in text
    assert "os.chown(p,10001,10001)" in text
    assert "os.chmod(p,0o700)" in text


def test_caddy_route_is_exact_private_and_overwrites_identity_header():
    text = (DEPLOY / "Caddyfile.production.snippet").read_text()
    assert "remote_ip 10.40.0.4" in text
    assert "method POST" in text
    assert "path /internal/api/v1/ai/auth/verify" in text
    assert "reverse_proxy qwen-auth-verifier:8095" in text
    overwrite = (
        'header_up X-Codestra-Client-Certificate-DER '
        '"{http.request.tls.client.certificate_der_base64}"'
    )
    assert text.count(overwrite) == 1
    assert text.count("header_up -X-Codestra-Client-Certificate") == 1
    assert "header_up -X-Codestra-Client-Certificate-DER" not in text
    assert "certificate_pem" not in text


def test_caddy_certificate_header_has_no_client_controlled_fallback():
    text = load_text("Caddyfile.production.snippet")
    assert "{http.request.header.X-Codestra-Client-Certificate}" not in text
    assert "{http.request.header.X-Codestra-Client-Certificate-DER}" not in text
    assert "{http.request.tls.client.certificate_der_base64}" in text


def test_runbook_requires_rollback_and_preserves_vicidial():
    text = (DEPLOY / "PRODUCTION_DEPLOYMENT.md").read_text()
    assert "automatic rollback" in text
    assert "Do not modify the" in text
    assert "VICIdial matcher" in text
    assert "do not add" in text
    assert "cleanup-runtime-secrets" in text
