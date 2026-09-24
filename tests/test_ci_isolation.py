import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.validate_ci_isolation import FLAGS, validate

ROOT = Path(__file__).resolve().parents[1]


def isolated():
    return {
        "DATABASE_URL": "postgresql+asyncpg://ci:synthetic@127.0.0.1:5432/middleware_rehearsal",
        "TEST_DATABASE_URL": "postgresql+asyncpg://ci:synthetic@127.0.0.1:5432/middleware_rehearsal",
        "REDIS_URL": "redis://127.0.0.1:6379/15", **{name: "false" for name in FLAGS},
    }


def test_validated_isolation_cli():
    result = subprocess.run([sys.executable, str(ROOT / "scripts/validate_ci_isolation.py")], env={**os.environ, **isolated()}, capture_output=True, text=True, check=False)
    assert result.returncode == 0


@pytest.mark.parametrize("name", [*FLAGS, "DATABASE_URL", "TEST_DATABASE_URL", "REDIS_URL"])
def test_missing_guard_variable_fails_closed(name):
    environ = isolated()
    environ.pop(name)
    with pytest.raises(ValueError):
        validate(environ)


@pytest.mark.parametrize("target", [
    "postgresql://ci:synthetic@production.invalid:5432/middleware_rehearsal",
    "postgresql://ci:synthetic@127.0.0.1:5432/customer_database",
    "postgresql://ci:synthetic@127.0.0.1:5432/middleware_rehearsal?host=production.invalid",
    "postgresql://ci:synthetic@127.0.0.1:bad/middleware_rehearsal",
])
def test_nonisolated_connection_target_is_rejected(target):
    with pytest.raises(ValueError):
        validate({**isolated(), "DATABASE_URL": target})


def test_workflow_blocks_real_runner_and_container_egress_without_rg_dependency():
    source = (ROOT / ".github/workflows/required-ci.yml").read_text()
    assert "python scripts/validate_ci_isolation.py" in source
    assert "for chain in OUTPUT FORWARD" in source
    assert 'iptables -I "$chain" 1 -d "$target" -j REJECT' in source
    assert 'iptables -C "$chain" -d "$target" -j REJECT' in source
    assert "! rg -n" not in source


def test_readiness_ci_preserves_positive_and_all_dependency_failure_cases():
    source = (ROOT / ".github/workflows/required-ci.yml").read_text()
    assert "redis@sha256:" in source
    assert "KEYCLOAK_JWKS_URL: http://127.0.0.1:8120/certs.json" in source
    assert "--bind 127.0.0.1" in source
    assert "audit_case healthy" in source and "200 8101" in source
    for name in ("wrong-credential", "dns-failure", "tcp-failure", "redis-failure", "keycloak-failure"):
        assert f"audit_case {name}" in source
        assert source.count(f"readiness-{name}.json") == 2


def test_manifest_gate_runs_after_locked_dependencies_and_before_pytest():
    source = (ROOT / "scripts/project_ci.sh").read_text()
    bootstrap = (ROOT / "scripts/run_ci.sh").read_text()
    install = source.index("--require-hashes -r requirements-test.txt")
    validate = source.index("python scripts/validate_codestra_manifest.py")
    tests = source.index("pytest -q tests")
    assert install < validate < tests
    assert "scripts/project_ci.sh" in bootstrap
    assert "python3 scripts/validate_codestra_manifest.py" not in bootstrap
