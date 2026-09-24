from pathlib import Path


def test_python_31214_build_does_not_reverse_integrated_security_fixes() -> None:
    dockerfile = Path("Dockerfile").read_text()
    builder = dockerfile.split("FROM ${PYTHON_BASE} AS python-builder", 1)[1].split(
        "FROM ${PYTHON_BASE} AS verified-python", 1
    )[0]

    assert "Python-3.12.14.tar.xz" in builder
    assert "5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a" in builder
    assert "patch -p1" not in builder
    assert "upstream-patches" not in builder
    assert "COPY security/python312" not in builder
    assert "curl=8.22.0-r0" in builder
    assert "unfiltered.replace" in builder
    assert 'pyexpat.EXPAT_VERSION == "expat_2.8.4"' in builder
