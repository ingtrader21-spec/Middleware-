import io
import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from scripts import build_mcr_certification_evidence as builder
from scripts import certify_mcr_release as cert


SHA = "a" * 40


def junit() -> bytes:
    cases = "".join(
        f'<testcase classname="{test.rsplit("::", 1)[0]}" name="{test.rsplit("::", 1)[1]}"/>'
        for test, _ in builder.SCENARIOS.values()
    )
    return f'<testsuite failures="0" errors="0" skipped="0">{cases}</testsuite>'.encode()


def archive(directory: Path) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for path in sorted(directory.iterdir()):
            zf.write(path, path.name)
    return stream.getvalue()


def test_builder_output_is_accepted_by_certifier(tmp_path: Path) -> None:
    results = tmp_path / "results.xml"
    results.write_bytes(junit())
    output = tmp_path / "evidence"
    manifest = builder.build(SHA, results, output)
    assert manifest["source_sha"] == SHA
    assert set(manifest["dependencies"]) == set(cert.DEPENDENCIES)
    assert cert.validate_bundle(archive(output), SHA)["source_sha"] == SHA


def test_builder_rejects_missing_scenario_test(tmp_path: Path) -> None:
    root = ET.fromstring(junit())
    root.remove(next(iter(root.findall("testcase"))))
    results = tmp_path / "results.xml"
    results.write_bytes(ET.tostring(root))
    with pytest.raises(ValueError, match="missing MCR scenario tests"):
        builder.build(SHA, results, tmp_path / "evidence")
