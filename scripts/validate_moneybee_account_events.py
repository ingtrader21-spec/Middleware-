#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = json.loads((ROOT / "contracts/event-envelope.schema.json").read_text())
SCHEMA = json.loads((ROOT / "contracts/moneybee-account-provisioned.schema.json").read_text())
ROUTING = json.loads((ROOT / "config/moneybee-account-event-routing.json").read_text())
PRODUCER = json.loads((ROOT / "config/moneybee-backend-producer-identity.json").read_text())

if "required" in CANONICAL:
    canonical_required = set(CANONICAL["required"])
else:
    assert CANONICAL["$ref"] == (
        "https://contracts.codestra.co/platform/event-envelope.v1.schema.json"
    )
    canonical_required = set()
assert canonical_required <= set(SCHEMA["required"])
assert SCHEMA["additionalProperties"] is False
assert SCHEMA["properties"]["specversion"]["const"] == "1.0"
assert SCHEMA["properties"]["type"]["const"] == "codestra.moneybee.account.provisioned"
assert SCHEMA["properties"]["source"]["const"] == "urn:codestra:moneybee-backend"
assert SCHEMA["properties"]["schema_version"]["const"] == 1
assert SCHEMA["properties"]["causation_id"]["type"] == "string"
actor = SCHEMA["properties"]["actor"]
assert actor["additionalProperties"] is False
assert actor["properties"]["type"]["const"] == "user"
data = SCHEMA["properties"]["data"]
assert data["additionalProperties"] is False
assert data["properties"]["email_verified"]["const"] is True
assert data["properties"]["membership_type"]["const"] == "BORROWER"

assert ROUTING["schemaVersion"] == 2
assert ROUTING["eventType"] == "codestra.moneybee.account.provisioned"
assert ROUTING["eventSchemaVersion"] == 1
assert ROUTING["source"]["idempotencyKey"] == "idempotency_key"
assert ROUTING["source"]["identityContract"] == "config/moneybee-backend-producer-identity.json"
assert ROUTING["source"]["requiredAudience"] == "middleware-api"
assert ROUTING["source"]["requiredScope"] == "moneybee.events.publish"
assert ROUTING["source"]["canonicalEnvelope"] == "contracts/event-envelope.schema.json"
assert ROUTING["authoritativeBoundaries"]["humanIdentityAuthority"] == "keycloak"
assert ROUTING["authoritativeBoundaries"]["crossSystemMutationBoundary"] == "middleware"
assert ROUTING["marketing"]["securityEmailPath"] == "prohibited"
assert ROUTING["marketing"]["mauticSynchronousIdentityMail"] is False

ownership = ROUTING["orchestrationOwnership"]
crm = ownership["baseCrmProjection"]
onboarding = ownership["borrowerOnboarding"]
assert crm == {
    "owner": "middleware",
    "destination": "odoo-integration",
    "command": "crm.contact.upsert.v1",
    "n8nMustNotDuplicate": True,
}
assert onboarding["owner"] == "n8n"
assert onboarding["trigger"] == "onboarding.started.v1"
assert onboarding["mayRequestBaseCrmProjection"] is False
assert set(onboarding["allowedResponsibilities"]) == {
    "onboarding.tasks",
    "document.followup",
    "operations.escalation",
    "marketing.consent.branch",
}

assert PRODUCER["clientId"] == "moneybee-backend"
assert PRODUCER["grantType"] == "client_credentials"
assert PRODUCER["targetClientId"] == "middleware-api"
assert PRODUCER["audience"] == "middleware-api"
assert PRODUCER["scopes"] == ["moneybee.events.publish"]
assert PRODUCER["maximumAccessTokenLifetimeSeconds"] <= 300
assert PRODUCER["refreshTokensAllowed"] is False
assert PRODUCER["fullScopeAllowed"] is False
assert PRODUCER["humanLoginAllowed"] is False
assert PRODUCER["keycloakAdminApiAccess"] is False
assert "identity.request" in PRODUCER["prohibitedScopes"]
assert "tenant.provision" in PRODUCER["prohibitedScopes"]

prohibited = set(ROUTING["prohibitedPayloadFields"])
required_prohibited = {
    "password",
    "verification_code",
    "otp",
    "reset_token",
    "access_token",
    "refresh_token",
    "smtp_password",
}
assert required_prohibited <= prohibited
assert prohibited.isdisjoint(data["properties"].keys())

routes = {route["destination"]: route for route in ROUTING["routes"]}
assert set(routes) == {"odoo-integration", "n8n-automation"}
assert routes["odoo-integration"]["command"] == "crm.contact.upsert.v1"
assert routes["n8n-automation"]["command"] == "onboarding.started.v1"
assert all(route["delivery"] == "transactional-outbox" for route in routes.values())

print("MONEYBEE_ACCOUNT_EVENT_CONTRACT=PASS")
