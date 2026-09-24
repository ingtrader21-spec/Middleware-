import json
from pathlib import Path


ROOT = Path("deploy/n8n/scraper")


def _documents():
    manifest = json.loads((ROOT / "workflow-manifest-v1.json").read_text())
    return manifest, [json.loads((ROOT / name).read_text()) for name in manifest["workflows"]]


def test_scraper_workflows_are_dedicated_inactive_and_no_message() -> None:
    manifest, workflows = _documents()
    allowed = set(manifest["allowed_node_types"])
    assert manifest["active_default"] is False
    assert manifest["production_delivery_enabled_default"] is False
    assert manifest["customer_communication_enabled"] is False
    assert len(workflows) == 2
    for workflow in workflows:
        assert workflow["active"] is False
        assert workflow["name"].startswith("ZZ_CDX_SCRAPER_CANARY_")
        assert {node["type"] for node in workflow["nodes"]} <= allowed


def test_scraper_workflows_have_no_external_or_vicidial_nodes() -> None:
    _, workflows = _documents()
    forbidden = ("email", "sms", "twilio", "httpRequest", "vicidial", "postgres", "redis")
    for workflow in workflows:
        node_types = " ".join(node["type"] for node in workflow["nodes"])
        assert not any(value.lower() in node_types.lower() for value in forbidden)
        if "DeadLetter" in workflow["id"]:
            assert "redrive_authorized:false" in json.dumps(workflow)
        else:
            assert "outbound_automation!==false" in json.dumps(workflow)
