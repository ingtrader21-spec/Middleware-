from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.qwen_auth_verifier import AUTH_PATH, create_app

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "deploy" / "qwen-auth-verifier"


def test_contract_matches_openapi_and_is_deterministic(monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("ab" * 32)
    secret.chmod(0o600)
    ca = tmp_path / "ca.crt"
    ca.write_text("not-used-for-schema")
    replay = tmp_path / "replay"
    replay.mkdir()
    values = {
        "QWEN_SERVICE_ID": "qwen-ai-01",
        "QWEN_HMAC_KEY_ID": "qwen-ai-01-hmac-20260804-01",
        "QWEN_HMAC_SECRET_FILE": str(secret),
        "QWEN_CLIENT_CA_FILE": str(ca),
        "QWEN_CERTIFICATE_SERIAL": "507396079750943841071109526780094961193782398461",
        "QWEN_CERTIFICATE_URI_SAN": "spiffe://codestra.internal/service/qwen-ai-01",
        "QWEN_CERTIFICATE_IP_SAN": "10.40.0.4",
        "QWEN_REPLAY_DIRECTORY": str(replay),
        "QWEN_TRUSTED_PROXY_CIDR": "172.18.0.0/16",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    first_schema = create_app().openapi()
    second_schema = create_app().openapi()
    assert set(first_schema["paths"]) == {AUTH_PATH}
    assert set(first_schema["paths"][AUTH_PATH]) == {"post"}
    first_normalized = json.dumps(
        first_schema, sort_keys=True, separators=(",", ":")
    ).encode()
    second_normalized = json.dumps(
        second_schema, sort_keys=True, separators=(",", ":")
    ).encode()
    assert hashlib.sha256(first_normalized).hexdigest() == hashlib.sha256(
        second_normalized
    ).hexdigest()
    contract = json.loads((PACKAGE / "auth-contract-v1.json").read_text())
    assert contract["method"] == "POST"
    assert contract["path"] == AUTH_PATH
    assert contract["scope"] == "ai.auth.verify/read-only"


def test_ingress_patch_is_private_exact_and_preserves_vicidial():
    patch = (PACKAGE / "Caddyfile.private-ingress.patch").read_text()
    readme = (PACKAGE / "README.md").read_text()
    assert "middleware.internal.codestra.agency" in patch
    assert "remote_ip 10.40.0.4" in patch
    assert "method POST" in patch
    assert "path /internal/api/v1/ai/auth/verify" in patch
    assert "requires the approved client CA" in readme
    assert "header_up -X-Codestra-Client-Certificate" in patch
    assert "X-Codestra-Client-Certificate-DER" in patch
    assert "{http.request.tls.client.certificate_der_base64}" in patch
    assert "certificate_pem" not in patch
    assert "header_up -X-Codestra-Client-Certificate-DER" not in patch
    assert patch.count("header_up X-Codestra-Client-Certificate-DER") == 1
    changed_lines = patch.splitlines()[2:]
    assert not any(line.startswith("-") for line in changed_lines)


def test_production_snippet_overwrites_spoofed_identity_header():
    snippet = (PACKAGE / "Caddyfile.production.snippet").read_text()
    assert "header_up -X-Codestra-Client-Certificate\n" in snippet
    assert "header_up -X-Codestra-Client-Certificate-DER" not in snippet
    assert snippet.count("header_up X-Codestra-Client-Certificate-DER") == 1
    assert "{http.request.tls.client.certificate_der_base64}" in snippet
    assert "certificate_pem" not in snippet


def test_compose_is_hardened_and_has_no_public_port_or_downstream_secret():
    source = (PACKAGE / "compose.candidate.yaml").read_text().lower()
    assert "ports:" not in source
    assert "read_only: true" in source
    assert "cap_drop: [all]" in source
    assert "no-new-privileges:true" in source
    assert 'user: "10001:10001"' in source
    assert ":/run/secrets/qwen-hmac:ro" in source
    for forbidden in ("odoo", "n8n", "vicidial", "postly"):
        assert forbidden not in source


def test_verifier_source_has_no_downstream_or_database_capability():
    source = (ROOT / "app" / "qwen_auth_verifier.py").read_text().lower()
    for forbidden in (
        "sqlalchemy",
        "asyncpg",
        "redis",
        "httpx",
        "requests",
        "subprocess",
        "odoo",
        "n8n",
        "vicidial",
        "postly",
    ):
        assert forbidden not in source
    assert "hmac.compare_digest" in source
    assert "os.o_excl" in source


def test_secret_manifest_contains_metadata_only():
    manifest = json.loads((PACKAGE / "secret-mount-manifest-v1.json").read_text())
    assert manifest["secret_value_present"] is False
    assert manifest["mount_mode"] == "read_only"
    assert manifest["container_file"] == "/run/secrets/qwen-hmac"
    assert "secret" not in manifest or manifest.get("secret") is None


def test_request_generator_reads_files_and_never_prints_secret():
    source = (ROOT / "scripts" / "generate_qwen_auth_probe.py").read_text()
    assert "read_bytes()" in source
    assert "print(secret" not in source
    assert "--cacert" in source and "--cert" in source and "--key" in source
    assert "--resolve" in source
