import json
from pathlib import Path

P = {
    "connect.crm.",
    "connect.social.",
    "connect.notification.",
    "connect.provisioning.",
    "connect.webhook.",
    "connect.audit.",
}
CAPS = {
    "connect.crm.": "ODOO_WRITE",
    "connect.social.": "SOCIAL_PUBLISH",
    "connect.notification.": "NOTIFICATION_DELIVERY",
    "connect.provisioning.": "PROVISIONING_WRITE",
    "connect.webhook.": "WEBHOOK_DELIVERY",
    "connect.audit.": "AUDIT_EXPORT",
}


def load(path):
    return json.loads(Path(path).read_text())


def test_connect_registry():
    c = load("config/control-plane-callers.v1.json")["callers"]["codestra-connect"]
    r = next(
        x
        for x in load("config/adapter-registry.v2.json")["adapters"]
        if x["id"] == "connect-router"
    )
    rows = [
        x
        for x in load("connectors/generated/command-registry.v1.json")["commands"]
        if x["prefix"] in P
    ]
    manifest = load("connectors/manifests/connect-router.connector.json")
    caps = load("config/capabilities.v2.json")["capabilities"]
    safety = load("config/platform-safety.v1.json")

    assert c["command_scope"] == "platform.command"
    assert c["status_scope"] == "platform.command.read"
    assert set(c["allowed_command_prefixes"]) == P
    assert c["allowed_targets"] == ["connect-router"]
    assert set(r["command_prefixes"]) == P
    assert manifest["repository"] == "ingtrader21-spec/Codestra-Connect"
    assert manifest["enabled_by_default"] is False
    assert manifest["direct_n8n_access"] is False
    assert {x["prefix"] for x in rows} == P
    assert all(x["readback_required"] for x in rows)
    assert {x["prefix"]: x["required_capability"] for x in rows} == CAPS
    for cap in {"AUDIT_EXPORT", "NOTIFICATION_DELIVERY", "WEBHOOK_DELIVERY"}:
        assert caps[cap] is False
        assert cap in safety["capability_gates"]
    assert safety["provider_kill_switches"]["connect-router"] is False

    authority = next(
        x for x in load("config/repository-authorities.v1.json")["authorities"]
        if x["component"] == "codestra-connect"
    )
    system = next(
        x for x in load("config/system-integration-registry.v4.json")["systems"]
        if x["component"] == "codestra-connect"
    )
    assert authority["github_repository_id"] == 1386450856
    assert system["github_repository_id"] == 1386450856
    assert system["adapter_id"] == "connect-router"
