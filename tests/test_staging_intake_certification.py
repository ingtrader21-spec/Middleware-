from __future__ import annotations

import copy
import importlib.util
import urllib.request
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "staging-intake-e2e-no-effect.py"
SOURCE_SHA = "a" * 40


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "staging_intake_e2e_no_effect",
        SCRIPT,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _version() -> dict[str, object]:
    return {
        "service": "middleware-api",
        "version": "1.0.0",
        "release_id": "release-1",
        "environment": "staging",
        "runtime_profile_id": "staging-intake-readonly",
        "source_sha": SOURCE_SHA,
        "git_sha": SOURCE_SHA,
        "image_digest": "sha256:" + ("b" * 64),
        "schema_head": "0069_progressive_tenant_rls",
        "schema_version": "0069_progressive_tenant_rls",
        "build_time": "2026-09-04T00:00:00Z",
        "build_timestamp": "2026-09-04T00:00:00Z",
        "configuration_checksum": "sha256:" + ("c" * 64),
    }


def _safety() -> dict[str, object]:
    version = _version()
    return {
        "schema_version": "1.1",
        "service": "middleware-api",
        "environment": "staging",
        "runtime_profile_id": version["runtime_profile_id"],
        "release": {
            "source_sha": version["source_sha"],
            "image_digest": version["image_digest"],
            "schema_head": version["schema_head"],
            "build_time": version["build_time"],
        },
        "persistence": {"in_memory": False},
        "dispatch": {
            "outbox_enabled": False,
            "nats_mode": "disabled",
            "temporal_worker_mode": "disabled",
        },
        "external_effects": {
            "SEND_EVENTS": False,
            "ODOO_WRITE": False,
            "LIVE_SMS_DELIVERY": False,
            "LIVE_EMAIL_DELIVERY": False,
            "LIVE_PSTN_DIALING": False,
        },
        "umbrella_controls": {
            "LIVE_ADVERTISING_ENABLED": False,
            "EXTERNAL_DELIVERY_ENABLED": False,
            "SOCIAL_PUBLISHING_ENABLED": False,
            "EXTERNAL_MODEL_CALLS_ENABLED": False,
            "N8N_EXTERNAL_PROVIDER_WRITES": False,
        },
        "production_dialing": "DISABLED",
        "production_activation_configured": False,
        "provider_effects_disabled": True,
        "all_external_effects_disabled": True,
        "staging_safe": True,
    }


def test_validate_base_url_rejects_committed_production_host() -> None:
    module = _load_script()
    with pytest.raises(SystemExit):
        module.validate_base_url(
            "https://api.codestra.co",
            approved_host="api.codestra.co",
            denied_hosts={"api.codestra.co"},
        )


@pytest.mark.parametrize(
    "value",
    [
        "http://staging-api.codestra.co",
        "https://user:pass@staging-api.codestra.co",
        "https://staging-api.codestra.co/path",
        "https://staging-api.codestra.co?token=secret",
        "https://staging-api.codestra.co#fragment",
        "https://staging-api.codestra.co:8443",
        "https://[::1]",
        "https://[fd00::1]",
        "https://127.0.0.1",
        "https://127.0.0.01",
        "https://staging-api.codestra.co:invalid",
    ],
)
def test_validate_base_url_rejects_unsafe_shapes(value: str) -> None:
    module = _load_script()
    with pytest.raises(SystemExit):
        module.validate_base_url(
            value,
            approved_host="staging-api.codestra.co",
            denied_hosts={"api.codestra.co"},
        )


def test_validate_base_url_rejects_unapproved_hostname() -> None:
    module = _load_script()
    with pytest.raises(SystemExit):
        module.validate_base_url(
            "https://attacker.example",
            approved_host="staging-api.codestra.co",
            denied_hosts={"api.codestra.co"},
        )


@pytest.mark.parametrize(
    "hostname",
    ["0x7f.0.0.1", "0177.0.0.1", "127.1"],
)
def test_validate_base_url_rejects_legacy_numeric_host_authority(
    hostname: str,
) -> None:
    module = _load_script()
    with pytest.raises(SystemExit):
        module.validate_base_url(
            f"https://{hostname}",
            approved_host=hostname,
            denied_hosts={"api.codestra.co"},
        )


def test_validate_base_url_accepts_isolated_https_staging_host() -> None:
    module = _load_script()
    assert (
        module.validate_base_url(
            "https://staging-api.codestra.co/",
            approved_host="staging-api.codestra.co",
            denied_hosts={"api.codestra.co"},
        )
        == "https://staging-api.codestra.co"
    )


def test_redirects_are_rejected_without_forwarding_protected_headers() -> None:
    module = _load_script()
    request = urllib.request.Request(
        "https://staging-api.codestra.co/version",
        headers={"Authorization": "Bearer protected-token"},
    )
    handler = module.FailClosedRedirectHandler()

    assert (
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://attacker.example/capture",
        )
        is None
    )


def test_validate_runtime_evidence_accepts_exact_fail_closed_staging() -> None:
    module = _load_script()
    evidence = module.validate_runtime_evidence(
        _version(),
        _safety(),
        expected_source_sha=SOURCE_SHA,
    )
    assert evidence["source_sha"] == SOURCE_SHA
    assert evidence["image_digest"] == "sha256:" + ("b" * 64)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        (("version", "source_sha"), "d" * 40),
        (("version", "image_digest"), "mutable-latest"),
        (("safety", "environment"), "production"),
        (("safety", "staging_safe"), False),
        (("safety", "production_activation_configured"), True),
    ],
)
def test_validate_runtime_evidence_rejects_identity_or_safety_drift(
    mutation: tuple[str, str],
    value: object,
) -> None:
    module = _load_script()
    version = _version()
    safety = _safety()
    target, key = mutation
    if target == "version":
        version[key] = value
    else:
        safety[key] = value

    with pytest.raises(SystemExit):
        module.validate_runtime_evidence(
            version,
            safety,
            expected_source_sha=SOURCE_SHA,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("git_sha", "d" * 40),
        ("schema_version", "0056_old"),
        ("build_timestamp", "2026-09-04T00:00:01Z"),
        ("configuration_checksum", "sha256:short"),
        ("release_id", ""),
        ("release_id", "unknown"),
        ("release_id", "release id with spaces"),
    ],
)
def test_validate_runtime_evidence_rejects_inconsistent_version_identity(
    field: str,
    value: object,
) -> None:
    module = _load_script()
    version = _version()
    version[field] = value
    with pytest.raises(SystemExit):
        module.validate_runtime_evidence(
            version,
            _safety(),
            expected_source_sha=SOURCE_SHA,
        )


def test_require_stable_runtime_rejects_configuration_drift() -> None:
    module = _load_script()
    before = module.validate_runtime_evidence(
        _version(),
        _safety(),
        expected_source_sha=SOURCE_SHA,
    )
    after = copy.deepcopy(before)
    after["configuration_checksum"] = "sha256:" + ("d" * 64)
    with pytest.raises(SystemExit):
        module.require_stable_runtime(before, after)


def test_validate_runtime_evidence_rejects_any_enabled_effect() -> None:
    module = _load_script()
    safety = _safety()
    effects = safety["external_effects"]
    assert isinstance(effects, dict)
    effects["LIVE_EMAIL_DELIVERY"] = True

    with pytest.raises(SystemExit):
        module.validate_runtime_evidence(
            _version(),
            safety,
            expected_source_sha=SOURCE_SHA,
        )


def test_validate_runtime_evidence_rejects_dispatch_activation() -> None:
    module = _load_script()
    safety = _safety()
    dispatch = safety["dispatch"]
    assert isinstance(dispatch, dict)
    dispatch["outbox_enabled"] = True

    with pytest.raises(SystemExit):
        module.validate_runtime_evidence(
            _version(),
            safety,
            expected_source_sha=SOURCE_SHA,
        )


def test_require_stable_runtime_rejects_mid_run_control_change() -> None:
    module = _load_script()
    before = module.validate_runtime_evidence(
        _version(),
        _safety(),
        expected_source_sha=SOURCE_SHA,
    )
    after = copy.deepcopy(before)
    safety = after["safety"]
    assert isinstance(safety, dict)
    safety["staging_safe"] = False

    with pytest.raises(SystemExit):
        module.require_stable_runtime(before, after)
