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
