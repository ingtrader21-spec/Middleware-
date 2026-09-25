from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.generate_postman import build as build_postman

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "postman" / "api-certification-manifest.v1.json"


def _sha(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def test_api_postman_certification_manifest_matches_committed_authority() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["schema"] == "codestra.middleware.api-postman-certification.v1"
    assert manifest["api_version"] == "/platform/v1"
    assert manifest["runtime"] == "middleware-integration-api:8095"
    assert manifest["status"] == "SOURCE_CERTIFIED"

    for key in ("openapi", "route_authority", "public_edge_contract", "postman"):
        item = manifest[key]
        assert _sha(item["path"]) == item["sha256"], key

    route_report = json.loads(
        (ROOT / manifest["route_authority"]["path"]).read_text(encoding="utf-8")
    )
    assert route_report["summary"]["operations"] == manifest["route_authority"]["operations"]
    assert (
        route_report["summary"]["DIRECT_EFFECT_BYPASSES"]
        == manifest["route_authority"]["direct_effect_bypasses"]
        == 0
    )

    edge = json.loads(
        (ROOT / manifest["public_edge_contract"]["path"]).read_text(encoding="utf-8")
    )
    routes = edge["routes"]
    by_class = {}
    for row in routes:
        by_class[row["classification"]] = by_class.get(row["classification"], 0) + 1

    assert len(routes) == manifest["public_edge_contract"]["routes"]
    assert by_class == {
        "shared_edge": manifest["public_edge_contract"]["shared_edge"],
        "private_only": manifest["public_edge_contract"]["private_only"],
        "denied": manifest["public_edge_contract"]["denied"],
    }

    assert not [
        row
        for row in routes
        if row["classification"] == "shared_edge"
        and str(row.get("path", "")).startswith(
            manifest["private_exposure"]["internal_prefix"]
        )
    ]
    assert not [
        row
        for row in routes
        if row["classification"] == "shared_edge"
        and row.get("path") == manifest["private_exposure"]["metrics_path"]
    ]

    collection, openapi_digest = build_postman()
    committed = json.loads(
        (ROOT / manifest["postman"]["path"]).read_text(encoding="utf-8")
    )
    assert collection == committed
    assert openapi_digest == manifest["openapi"]["sha256"]

    assert manifest["production_defaults"] == {
        "allow_mutations": False,
        "provider_effects": 0,
        "production_effects": 0,
        "production_go": "NO",
    }


def _walk_postman_items(items):
    for item in items:
        if "request" in item:
            yield item
        yield from _walk_postman_items(item.get("item", []))


def test_generated_postman_is_safe_by_default_and_assertive() -> None:
    collection, _ = build_postman()
    variables = {row["key"]: row.get("value") for row in collection["variable"]}
    assert variables["allow_mutating_requests"] == "false"

    requests = list(_walk_postman_items(collection["item"]))
    assert requests
    for item in requests:
        method = item["request"]["method"]
        events = item.get("event", [])
        assert any(event.get("listen") == "test" for event in events), item["name"]
        if method not in {"GET", "HEAD", "OPTIONS"}:
            prerequest = [event for event in events if event.get("listen") == "prerequest"]
            assert prerequest, item["name"]
            source = "\n".join(prerequest[0]["script"]["exec"])
            assert "allow_mutating_requests" in source
            assert "skipRequest" in source


def test_db_public_exposure_checks_distinguish_local_from_edge() -> None:
    collection = json.loads((ROOT / "postman/collections/Middleware-V3-Database-Certification.postman_collection.json").read_text(encoding="utf-8"))
    folder = next(row for row in collection["item"] if row["name"].startswith("05 "))
    for item in folder["item"]:
        source = "\n".join(item["event"][0]["script"]["exec"])
        assert "localProfile" in source
        assert "[401,403,404]" in source
