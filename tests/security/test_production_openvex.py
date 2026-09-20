from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/security/validate-production-openvex.py"
SPEC = importlib.util.spec_from_file_location("production_openvex", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
ValidationError = module.ValidationError
SHA = "4db1c245c1733e4abc7ea695d76862ffdc3fd698"
DIGEST = "sha256:" + "a" * 64
IDENTITY = "https://github.com/ingtrader21-spec/Middleware-/.github/workflows/security-owner-decision-sign.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def bash_executable() -> str:
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"), "Programs", "Git", "bin", "bash.exe"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return "bash"


def document() -> dict:
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://evidence.codestra.invalid/production/test",
        "author": "Independent Security Owner",
        "role": "Security Owner",
        "timestamp": "2026-08-14T00:00:00Z",
        "last_updated": "2026-08-14T00:00:00Z",
        "version": 1,
        "metadata": {"source_sha": SHA, "image_digest": DIGEST},
        "statements": [{
            "vulnerability": {"name": "CVE-2026-0001"},
            "products": [{"@id": f"pkg:oci/codestra-middleware@{DIGEST.replace(':', '%3A')}"}],
            "status": "fixed",
            "timestamp": "2026-08-14T00:00:00Z",
        }],
    }


def test_exact_openvex_is_accepted() -> None:
    module.validate(document(), source_sha=SHA, image_digest=DIGEST)


@pytest.mark.parametrize("mutation", ["wrong_sha", "missing_author", "missing_statements", "wrong_digest"])
def test_invalid_openvex_is_rejected(mutation: str) -> None:
    value = document()
    if mutation == "wrong_sha":
        value["metadata"]["source_sha"] = "b" * 40
    elif mutation == "missing_author":
        value["author"] = ""
    elif mutation == "missing_statements":
        value["statements"] = []
    else:
        value["statements"][0]["products"][0]["@id"] = "pkg:oci/wrong@sha256%3A" + "b" * 64
    with pytest.raises(ValidationError):
        module.validate(value, source_sha=SHA, image_digest=DIGEST)


def write_artifact(path: Path, *, signer: str = IDENTITY, issuer: str = ISSUER) -> None:
   vex = json.dumps(document(), sort_keys=True, separators=(",", ":")) + "\n"
   (path / "openvex.json").write_bytes(vex.encode("utf-8"))
   bundle = {"signer": signer, "issuer": issuer, "payload_sha256": hashlib.sha256(vex.encode()).hexdigest()}
   (path / "openvex.sigstore.json").write_bytes(json.dumps(bundle, separators=(",", ":")).encode("utf-8"))
   sums = []
   for name in ("openvex.json", "openvex.sigstore.json"):
       sums.append(f"{hashlib.sha256((path / name).read_bytes()).hexdigest()}  {name}\n")
   (path / "SHA256SUMS").write_bytes("".join(sums).encode("utf-8"))


def fake_cosign(path: Path) -> Path:
   script = path / "cosign"
   script.write_text("""#!/usr/bin/env python
import hashlib,json,sys

a=sys.argv; b=json.load(open(a[a.index('--bundle')+1])); payload=a[-1]
expected_identity=a[a.index('--certificate-identity')+1]
expected_issuer=a[a.index('--certificate-oidc-issuer')+1]
valid=(b.get('signer')==expected_identity and b.get('issuer')==expected_issuer and b.get('payload_sha256')==hashlib.sha256(open(payload,'rb').read()).hexdigest())
raise SystemExit(0 if valid else 1)
""", encoding="utf-8", newline="\n")
   script.chmod(0o755)
   return script


def verify(path: Path, cosign: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["COSIGN_BIN"] = str(cosign)
    for candidate in (
        os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"), "Programs", "Git", "bin"),
        r"C:\Program Files\Git\bin",
        r"C:\Program Files\Git\usr\bin",
    ):
        if os.path.isdir(candidate):
            env["PATH"] = candidate + os.pathsep + env.get("PATH", "")
            break
    return subprocess.run(
        [bash_executable(), "scripts/security/verify-production-openvex.sh", str(path), SHA, DIGEST],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )


def test_complete_signed_artifact_verifies(tmp_path: Path) -> None:
    write_artifact(tmp_path)
    assert verify(tmp_path, fake_cosign(tmp_path)).returncode == 0


@pytest.mark.parametrize("failure", ["wrong_signer", "wrong_issuer", "altered", "checksum", "unsigned"])
def test_artifact_authenticity_failures_are_rejected(tmp_path: Path, failure: str) -> None:
    signer = "wrong" if failure == "wrong_signer" else IDENTITY
    issuer = "wrong" if failure == "wrong_issuer" else ISSUER
    write_artifact(tmp_path, signer=signer, issuer=issuer)
    cosign = fake_cosign(tmp_path)
    if failure == "altered":
        (tmp_path / "openvex.json").write_text((tmp_path / "openvex.json").read_text() + " ")
    elif failure == "checksum":
        (tmp_path / "SHA256SUMS").write_text("0" * 64 + "  openvex.json\n")
    elif failure == "unsigned":
        (tmp_path / "openvex.sigstore.json").unlink()
    assert verify(tmp_path, cosign).returncode != 0


def test_workflow_produces_verifier_contract() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-decision-sign.yml").read_text()
    assert "production-openvex-${{ inputs.production_source_sha }}" in workflow
    assert "openvex.sigstore.json" in workflow
    assert "certificate-identity \"${identity}\"" in workflow
    assert "certificate-oidc-issuer \"${issuer}\"" in workflow
