from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_postman.py"
SPEC = importlib.util.spec_from_file_location("middleware_postman_generator", MODULE_PATH)
assert SPEC and SPEC.loader
postman = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = postman
SPEC.loader.exec_module(postman)


def test_generated_collection_has_fail_closed_effect_guard() -> None:
    collection, _ = postman.build()
    prerequest = next(event for event in collection["event"] if event["listen"] == "prerequest")
    script = "\n".join(prerequest["script"]["exec"])
    assert "RUN_EFFECTFUL" in script
    assert "pm.execution.skipRequest()" in script
    values = {row["key"]: row["value"] for row in collection["variable"]}
    assert values["RUN_EFFECTFUL"] == "false"


def test_generated_collection_has_global_response_assertions() -> None:
    collection, _ = postman.build()
    test_event = next(event for event in collection["event"] if event["listen"] == "test")
    script = "\n".join(test_event["script"]["exec"])
    assert "response is not 5xx" in script
    assert "X-Request-ID" in script
    assert "X-Correlation-ID" in script


def test_generated_collection_defaults_to_loopback_and_empty_tokens() -> None:
    collection, _ = postman.build()
    values = {row["key"]: row["value"] for row in collection["variable"]}
    assert values["base_url"] == "http://127.0.0.1:8095"
    assert values["bearer_token"] == ""
    assert values["db_read_token"] == ""
    assert values["db_verify_token"] == ""


def test_generated_collection_matches_checked_in_artifact() -> None:
    collection, _ = postman.build()
    assert postman.OUTPUT.read_text(encoding="utf-8") == postman._json(collection)
