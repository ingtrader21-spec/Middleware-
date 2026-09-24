from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.validate_codestra_manifest import REQUIRED_FILES, validate

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/platform/service.v1.schema.json"


@pytest.fixture
def bundle(tmp_path):
    shutil.copytree(ROOT / ".codestra", tmp_path / ".codestra")
    return tmp_path / ".codestra"


def cli(bundle):
    return subprocess.run([sys.executable, str(ROOT / "scripts/validate_codestra_manifest.py"), str(bundle / "service.yaml"), "--schema", str(SCHEMA)], capture_output=True, text=True, check=False)


def test_complete_repository_contract_runs_cli():
    result = cli(ROOT / ".codestra")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MANIFEST_VALID=PASS" in result.stdout


@pytest.mark.parametrize("name", sorted(REQUIRED_FILES))
@pytest.mark.parametrize("invalid", [None, "", "[broken:", "null\n", "{}\n"])
def test_every_file_is_required_and_validated(bundle, name, invalid):
    file = bundle / name
    if invalid is None:
        file.unlink()
    else:
        file.write_text(invalid)
    result = cli(bundle)
    assert result.returncode != 0
    assert "MANIFEST_VALID=PASS" not in result.stdout


@pytest.mark.parametrize("filename,mutation", [
    ("dependencies.yaml", lambda d: d["items"].append(d["items"][0])),
    ("dependencies.yaml", lambda d: d["items"][0].update(id="unknown-service")),
    ("dependencies.yaml", lambda d: d["items"][1].update(requiredForReadiness=False)),
    ("permissions.yaml", lambda d: d["production"].update(selfApprovalAllowed=True)),
    ("permissions.yaml", lambda d: d["scopes"].update(write=["platform.services.read"])),
    ("observability.yaml", lambda d: d["logs"].update(redact=[])),
    ("observability.yaml", lambda d: d["metrics"].update(path="/wrong")),
    ("integration.yaml", lambda d: d["odoo"].update(unrestrictedRpcAccess=True)),
    ("integration.yaml", lambda d: d["externalEffects"].update(pstn="enabled")),
    ("slo.yaml", lambda d: d["objectives"].update(availability=101)),
    ("slo.yaml", lambda d: d.update(profile="unmatched-profile")),
])
def test_semantic_and_cross_file_validation(bundle, filename, mutation):
    file = bundle / filename
    document = yaml.safe_load(file.read_text())
    mutation(document)
    file.write_text(yaml.safe_dump(document))
    assert validate(bundle / "service.yaml", SCHEMA)


def test_duplicate_yaml_keys_fail_closed(bundle):
    file = bundle / "permissions.yaml"
    file.write_text(file.read_text() + "kind: Permissions\n")
    result = cli(bundle)
    assert result.returncode != 0
    assert "MANIFEST_VALID=FAIL" in result.stdout
