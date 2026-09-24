"""Fail-closed source gate for the inactive lead-automation n8n artifact."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = json.loads((ROOT / "lead-automation-generic-v1.json").read_text())
MANIFEST = json.loads((ROOT / "workflow-manifest-v1.json").read_text())
BINDING = json.loads((ROOT / "binding-registration-v1.json").read_text())
PROVENANCE = json.loads((ROOT / "schemas/provenance-manifest-v1.json").read_text())
CALLBACK_AUTH = json.loads((ROOT / "callback-auth-manifest-v2.json").read_text())
NODE_ALLOWLIST = json.loads((ROOT / "node-allowlist-v1.json").read_text())

assert WORKFLOW["name"] == MANIFEST["workflow_logical_name"]
assert WORKFLOW["id"] == MANIFEST["source_import_placeholder_id"]
assert MANIFEST["workflow_id"] is None
assert WORKFLOW["active"] is False
assert WORKFLOW["meta"]["workflow_active_default"] is False
assert WORKFLOW["meta"]["binding_enabled_default"] is False
assert WORKFLOW["meta"]["lead_automation_enabled_default"] is False
assert all(node.get("disabled") is True for node in WORKFLOW["nodes"])
assert BINDING["binding_key"] == "n8n.leads.ingest"
assert BINDING["environment"] == "staging"
assert BINDING["enabled"] is False
assert BINDING["lead_automation_enabled"] is False
assert BINDING["maximum_attempts"] == MANIFEST["maximum_callback_attempts"] == 5
assert "workflow_id" not in BINDING
assert "credential" not in BINDING

allowed = set(NODE_ALLOWLIST["approved_node_types"])
assert allowed == set(MANIFEST["node_type_allowlist"])
node_types = [node["type"] for node in WORKFLOW["nodes"]]
assert set(node_types) <= allowed
assert len([kind for kind in node_types if kind == "n8n-nodes-base.httpRequest"]) == 1
prohibited_fragments = (
    "odoo",
    "postgres",
    "mysql",
    "email",
    "twilio",
    "whatsapp",
    "calendar",
    "appointment",
    "asterisk",
    "vicidial",
    "recording",
)
assert not [kind for kind in node_types if any(part in kind.lower() for part in prohibited_fragments)]

http_node = next(node for node in WORKFLOW["nodes"] if node["type"] == "n8n-nodes-base.httpRequest")
assert http_node["parameters"]["method"] == "POST"
assert http_node["parameters"]["url"] == (
    "={{ $env.MIDDLEWARE_INTERNAL_URL + '/api/v1/lead-automation/results' }}"
)
assert http_node.get("onError") == "continueRegularOutput"

source = json.dumps(WORKFLOW, sort_keys=True)
code_source = "\n".join(
    node.get("parameters", {}).get("jsCode", "") for node in WORKFLOW["nodes"]
)
assert "$env.LEAD_AUTOMATION_CALLBACK_HMAC_SECRET" in source
assert "createHmac('sha256',secret)" in source
assert "[version,method,path,timestamp,nonce,identity,audience,e.environment,scope,e.idempotency_key,bodyHash].join('\\n')" in code_source
assert CALLBACK_AUTH["signature_version"] == "HMAC-V2"
assert len(CALLBACK_AUTH["canonical_field_order"]) == 11
assert CALLBACK_AUTH["callback_scope"] == "lead-automation.results.write"
assert "Re-sign callback retry" in {node["name"] for node in WORKFLOW["nodes"]}
assert "65.109.65.169" not in source
assert "65.21.67.207" not in source
assert not re.search(r"https?://", source)
assert not re.search(r"BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY", source)

assert PROVENANCE["source_repository"] == "appolon1908-hue/Middleware-"
assert PROVENANCE["source_pull_request"] == 65
assert PROVENANCE["source_head_sha"] == "da215762375614aa617bf838f9e4974ac2ad7c68"
assert PROVENANCE["callback_auth_source_head"] == "04fa56f4c8bb8caea3e5281816a2986bcb47ba05"
assert PROVENANCE["odoo_source_head"] == "384d175eb32bc87f34b9c736453db44c2d151b1a"
assert PROVENANCE["contract_version"] == "1.0"
for entry in PROVENANCE["schema_files"]:
    schema = ROOT / "schemas" / entry["schema_filename"]
    assert schema.is_file()
    assert hashlib.sha256(schema.read_bytes()).hexdigest() == entry["schema_sha256"]

for required_doc in ("README.md", "SECURITY.md", "ROLLBACK.md"):
    assert (ROOT / required_doc).is_file()

print("lead automation n8n source gates: PASS")
