import json
from pathlib import Path
P={"connect.crm.","connect.social.","connect.notification.","connect.provisioning.","connect.webhook.","connect.audit."}
def load(p): return json.loads(Path(p).read_text())
def test_connect_registry():
 c=load("config/control-plane-callers.v1.json")["callers"]["codestra-connect"]
 r=next(x for x in load("config/adapter-registry.v2.json")["adapters"] if x["id"]=="connect-router")
 rows=[x for x in load("connectors/generated/command-registry.v1.json")["commands"] if x["prefix"] in P]
 assert set(c["allowed_command_prefixes"])==P
 assert c["allowed_targets"]==["connect-router"]
 assert set(r["command_prefixes"])==P
 assert {x["prefix"] for x in rows}==P
 assert all(x["readback_required"] for x in rows)
