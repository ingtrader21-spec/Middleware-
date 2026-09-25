from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.platform.staging_certification import StagingCertificationError, validate_staging_preflight


ROOT = Path(__file__).resolve().parents[1]


def test_repository_staging_preflight_is_test_syn_only() -> None:
    result = validate_staging_preflight(ROOT)
    assert result.profile_id == "codestra-middleware-staging-v1"
    assert result.campaign == "TEST_SYN"
    assert result.listener_port == 8095
    assert result.direct_effect_bypasses == 0
    assert result.provider_effects == 0


def _copy_fixture(root: Path) -> None:
    for relative in (
        "config/environments/staging.runtime.env.example",
        "config/platform-safety.v1.json",
        "config/route-authority-report.v1.json",
        "scripts/certify_test_syn.py",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def test_route_authority_rejects_legacy_8080(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "route-authority-report.v1.json"
    routes = json.loads(path.read_text(encoding="utf-8"))
    routes["listener_port"] = 8080
    path.write_text(json.dumps(routes), encoding="utf-8")

    with pytest.raises(StagingCertificationError, match="8095"):
        validate_staging_preflight(tmp_path)


def test_non_test_syn_tenant_is_rejected(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "platform-safety.v1.json"
    safety = json.loads(path.read_text(encoding="utf-8"))
    safety["synthetic_tenants"] = ["TEST_SYN", "REAL_CAMPAIGN"]
    path.write_text(json.dumps(safety), encoding="utf-8")

    with pytest.raises(StagingCertificationError, match="TEST_SYN only"):
        validate_staging_preflight(tmp_path)


def test_effect_flag_enablement_is_rejected(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "environments" / "staging.runtime.env.example"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("SMS_DELIVERY_ENABLED=false", "SMS_DELIVERY_ENABLED=true"), encoding="utf-8")
    with pytest.raises(StagingCertificationError, match="SMS_DELIVERY_ENABLED"):
        validate_staging_preflight(tmp_path)


def test_direct_effect_bypass_is_rejected(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "route-authority-report.v1.json"
    routes = json.loads(path.read_text(encoding="utf-8"))
    routes["summary"]["DIRECT_EFFECT_BYPASSES"] = 1
    path.write_text(json.dumps(routes), encoding="utf-8")
    with pytest.raises(StagingCertificationError, match="direct effect bypasses"):
        validate_staging_preflight(tmp_path)


def test_wrong_integration_service_is_rejected(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "route-authority-report.v1.json"
    routes = json.loads(path.read_text(encoding="utf-8"))
    routes["service"] = "legacy-middleware"
    path.write_text(json.dumps(routes), encoding="utf-8")
    with pytest.raises(StagingCertificationError, match="service mismatch"):
        validate_staging_preflight(tmp_path)


def test_certifier_must_keep_legacy_8080_rejection(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "scripts" / "certify_test_syn.py"
    path.write_text(path.read_text(encoding="utf-8").replace("legacy port 8080", "legacy port"), encoding="utf-8")
    with pytest.raises(StagingCertificationError, match="reject legacy port 8080"):
        validate_staging_preflight(tmp_path)


def test_duplicate_staging_env_keys_are_rejected(tmp_path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "config" / "environments" / "staging.runtime.env.example"
    path.write_text(path.read_text(encoding="utf-8") + "\nAPP_ENV=staging\n", encoding="utf-8")
    with pytest.raises(StagingCertificationError, match="duplicate env key: APP_ENV"):
        validate_staging_preflight(tmp_path)
