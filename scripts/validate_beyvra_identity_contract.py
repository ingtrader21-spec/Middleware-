#!/usr/bin/env python3
"""Fail-closed validation for the Beyvra to Middleware identity event."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "beyvra-identity-event-contract.json"
SCHEMA = ROOT / "contracts" / "beyvra-identity-provisioned.schema.json"
CONNECTIVITY = ROOT / "config" / "connectivity-map.json"


def require(value, message):
    if not value:
        raise SystemExit(f"BEYVRA_IDENTITY_CONTRACT_ERROR={message}")


def main():
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    connectivity = json.loads(CONNECTIVITY.read_text(encoding="utf-8"))
    require(contract["schemaVersion"] == 1, "schema version changed")
    require(contract["state"] == "contract-only-runtime-unverified", "runtime state overstated")
    require(contract["source"] == {
        "repository": "appolon1908-hue/beyvra-backend",
        "eventType": "identity.account.provisioned",
        "schema": "contracts/beyvra-identity-provisioned.schema.json",
    }, "source contract changed")
    transport = contract["transport"]
    require(transport["kind"] == "nats-jetstream", "transport changed")
    require(transport["subject"] == "identity.account.provisioned", "subject changed")
    require(transport["delivery"] == "at_least_once", "delivery changed")
    require(transport["messageIdField"] == "event_id", "message id changed")
    require(transport["publisher"] == "beyvra-backend", "publisher changed")
    require(transport["consumer"] == "middleware-worker", "consumer changed")
    require(transport["runtimeUrlEnvironment"] == "NATS_URL", "runtime URL must remain external")

    normalization = contract["normalization"]
    require(
        normalization["canonicalEnvelope"]
        == "contracts/platform/event-envelope.v1.schema.json",
        "canonical envelope changed",
    )
    require(normalization["canonicalType"] == "codestra.identity.account.provisioned", "canonical type changed")
    require(normalization["canonicalSource"] == "beyvra-backend", "canonical source changed")
    require(normalization["canonicalTenant"] == "beyvra", "tenant changed")

    allowed = {"identity_ref", "local_user_ref", "roles", "authority"}
    require(set(contract["privacy"]["allowedPayloadFields"]) == allowed, "payload allowlist changed")
    required_forbidden = {
        "email", "password", "otp", "reset_token", "authorization_code",
        "access_token", "refresh_token", "id_token", "code_verifier",
    }
    require(set(contract["privacy"]["forbiddenFields"]) == required_forbidden, "forbidden fields changed")
    require(set(schema["properties"]["payload"]["required"]) == allowed, "schema payload fields changed")
    require(set(schema["properties"]["payload"]["properties"]) == allowed, "schema payload properties changed")
    require(schema["properties"]["payload"]["additionalProperties"] is False, "payload must fail closed")
    require(schema["properties"]["event_type"]["const"] == transport["subject"], "schema subject mismatch")
    require(schema["properties"]["tenant_ref"]["const"] == "beyvra", "schema tenant mismatch")

    effects = contract["effects"]
    require(effects == {
        "middlewareIdentityProjectionAllowed": True,
        "odooWriteAllowed": False,
        "n8nDispatchAllowed": False,
        "passwordOrRecoveryProcessingAllowed": False,
    }, "downstream authority changed")
    require(contract["httpBoundary"]["synchronousAuthEndpoint"] is None, "synchronous auth must bypass Middleware")
    require(contract["httpBoundary"]["identityWebhook"] is None, "identity is not an HTTP webhook")
    expected_connection = {
        "id": "beyvra-to-workers-identity-events",
        "source_branch": "integration/beyvra",
        "target_branch": "core/workers-scheduler",
        "direction": "queue",
        "transport": "nats_jetstream",
        "authentication": "nats_tls_service_identity",
        "reliability": "at_least_once",
        "owner_branch": "integration/beyvra",
        "runtime_status": "verification_only",
        "contract": "contracts/beyvra-identity-provisioned.schema.json",
    }
    require(expected_connection in connectivity["connections"], "connectivity route changed")
    serialized = (CONTRACT.read_text(encoding="utf-8") + SCHEMA.read_text(encoding="utf-8")).lower()
    require("auth.codestra.agency" not in serialized, "legacy issuer found")
    require("moneybee" not in serialized, "unrelated product found")
    print("BEYVRA_IDENTITY_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
