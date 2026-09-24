from pathlib import Path


def test_middleware_runtime_clears_base_entrypoint() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile[dockerfile.index("AS runtime\n") :]
    assert "ENTRYPOINT []" in runtime
    assert 'CMD ["/opt/venv/bin/python", "-m", "app.entrypoints.integration_api"]' in runtime


def test_websocket_runtime_clears_base_entrypoint() -> None:
    dockerfile = Path("websocket_gateway/Dockerfile").read_text(encoding="utf-8")
    assert "ENTRYPOINT []" in dockerfile
    assert 'CMD ["/opt/venv/bin/python", "-m", "uvicorn", "app:app"' in dockerfile
