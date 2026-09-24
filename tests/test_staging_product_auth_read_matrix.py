from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "staging_product_auth_read_matrix.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "staging_product_auth_read_matrix",
        SCRIPT,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def encoded(value: dict[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def token(claims: dict[str, object]) -> str:
    return (
        encoded({"alg": "RS256", "typ": "JWT"})
        + "."
        + encoded(claims)
        + ".signature"
    )


def valid_claims(
    *,
    client_id: str = "moneybee-backend",
    scope: str = "moneybee.middleware.status.read",
) -> dict[str, object]:
    return {
        "iss": "https://auth.codestra.co/realms/codestra",
        "sub": f"service-account-{client_id}",
        "aud": ["middleware-api"],
        "azp": client_id,
        "iat": 1000,
        "exp": 1300,
        "scope": scope,
        "tenant_id": "tenant-test",
    }


def test_source_performs_only_token_post_and_operation_gets() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.count('method="POST"') == 1
    assert source.count('method="GET"') == 1
    assert "grant_type" in source and "client_credentials" in source
    assert "/v1/commands" not in source
    assert "/api/v1/control/identity-probes/{operation_id}" in source
    assert "provider_calls" in source
    assert '"command_posts": 0' in source
    assert '"business_mutations": 0' in source
    assert "AUTH_MATRIX_COMMAND_POSTS=0" in source
    assert "AUTH_MATRIX_PROVIDER_CALLS=0" in source


def test_matrix_client_registry_is_policy_derived_and_complete() -> None:
    module = load_module()
    clients = module._load_policy()
    required_products = {
        "moneybee-backend",
        "breero-backend",
        "larim-a-backend",
        "transportation-backend",
        "beyvra-backend",
        "social-codestra",
    }
    required_provider_callers = {
        "codestra-ai",
        "codestra-communication",
        "codestra-marketing",
        "codestra-social",
    }
    assert required_products <= set(clients)
    assert required_provider_callers <= set(clients)
    assert "n8n-automation" in clients
    assert "kong-gateway" not in clients
    assert all(
        client.secret_environment.startswith("AUTH_MATRIX_SECRET_")
        for client in clients.values()
    )


def test_provider_callers_cannot_use_generic_mutation_authority() -> None:
    policy = json.loads(
        (ROOT / "config/control-plane-callers.v1.json").read_text(
            encoding="utf-8"
        )
    )
    providers = {
        "codestra-ai",
        "codestra-communication",
        "codestra-marketing",
        "codestra-social",
    }
    for client_id in providers:
        caller = policy["callers"][client_id]
        assert caller["connector_commands_allowed"] is False
        assert caller["command_scope"].endswith(".denied")
        assert caller["status_scope"].endswith(".denied")
        assert caller["allowed_command_prefixes"] == []
        assert caller["allowed_targets"] == []
        assert caller["staging_auth_matrix"] is True


def test_valid_claim_shape_requires_exact_short_lived_token() -> None:
    module = load_module()
    claims = valid_claims()
    tenant = module.validate_claim_shape(
        claims,
        client_id="moneybee-backend",
        required_scope="moneybee.middleware.status.read",
        now=1100,
    )
    assert tenant == "tenant-test"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("iss", "https://wrong.invalid/realm", "issuer"),
        ("aud", ["moneybee-api"], "audience"),
        ("aud", ["middleware-api", "extra-audience"], "audience"),
        ("azp", "social-codestra", "azp"),
        ("sub", "", "subject"),
        ("iat", 1200, "issued-at"),
        ("exp", 1401, "lifetime"),
        ("exp", 1100, "expired"),
        ("nbf", 1200, "not yet valid"),
        ("scope", "moneybee.middleware.command.write", "scope"),
        ("tenant_id", "*", "tenant_id"),
        ("tenant_id", "", "tenant_id"),
    ],
)
def test_invalid_claim_shapes_fail_closed(
    field: str,
    value: object,
    message: str,
) -> None:
    module = load_module()
    claims = valid_claims()
    claims[field] = value
    with pytest.raises(module.MatrixError, match=message):
        module.validate_claim_shape(
            claims,
            client_id="moneybee-backend",
            required_scope="moneybee.middleware.status.read",
            now=1100,
        )


def test_wrong_azp_and_cross_client_scope_confusion_fail_closed() -> None:
    module = load_module()
    claims = valid_claims(
        client_id="codestra-ai",
        scope="social.publish.request",
    )
    with pytest.raises(module.MatrixError, match="scope"):
        module.validate_claim_shape(
            claims,
            client_id="codestra-ai",
            required_scope="ai.inference.request",
            now=1100,
        )
    with pytest.raises(module.MatrixError, match="azp"):
        module.validate_claim_shape(
            claims,
            client_id="codestra-social",
            required_scope="social.publish.request",
            now=1100,
        )


def test_jwt_decode_and_signature_tamper_do_not_require_secret() -> None:
    module = load_module()
    original = token(valid_claims())
    claims = module.decode_unverified_claims(original)
    assert claims["azp"] == "moneybee-backend"
    changed = module.tamper_signature(original)
    assert changed != original
    assert changed.split(".")[:2] == original.split(".")[:2]


def test_negative_fixture_inventory_is_exact_and_private(tmp_path: Path) -> None:
    module = load_module()
    fixtures = {
        case: {
            "token": token(
                valid_claims(
                    client_id="codestra-ai",
                    scope="ai.inference.request",
                )
            ),
            "tenant_id": "tenant-negative",
        }
        for case in module.NEGATIVE_FIXTURE_CASES
    }
    path = tmp_path / "negative-tokens.json"
    path.write_text(json.dumps(fixtures), encoding="utf-8")
    loaded = module._load_negative_fixtures(str(path))
    assert set(loaded) == set(module.NEGATIVE_FIXTURE_CASES)
    assert all(item["token"] for item in loaded.values())


def test_evidence_contract_records_no_tokens_secrets_or_raw_tenants() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"tokens_recorded": False' in source
    assert '"secrets_recorded": False' in source
    assert "tenant_sha256" in source
    assert '"tenant_id": tenant_id' not in source
    assert "fixture['token']" in source
    assert '"token": fixture' not in source


def test_staging_marker_release_identity_and_https_endpoints_are_required() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'AUTH_MATRIX_ENVIRONMENT") != "staging"' in source
    assert "AUTH_MATRIX_GATEWAY_BASE_URL" in source
    assert "AUTH_MATRIX_TOKEN_ENDPOINT" in source
    assert "AUTH_MATRIX_SOURCE_SHA" in source
    assert "AUTH_MATRIX_IMAGE_DIGEST" in source
    assert "must be an HTTPS URL without embedded credentials" in source


def test_unsupported_forwarding_header_cannot_replace_authorization() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"unsupported_forwarding_header_only"' in source
    assert '"X-Forwarded-Authorization"' in source
    assert "authorization=None" in source
    assert "expected_status=401" in source


def test_subset_runs_are_not_certification_eligible() -> None:
    module = load_module()
    clients = module._load_policy()
    selected = module._selected_clients(
        clients,
        next(iter(clients)),
    )
    assert len(selected) == 1
    assert {item.client_id for item in selected} != set(clients)
