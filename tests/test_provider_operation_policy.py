from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provider_policy_validator",
    ROOT / "scripts" / "validate_provider_operation_policy.py",
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ProviderOperationPolicyTests(unittest.TestCase):
    policy: dict[str, Any]
    identity: dict[str, Any]
    safety: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(VALIDATOR.POLICY.read_text(encoding="utf-8"))
        cls.identity = json.loads(VALIDATOR.IDENTITY.read_text(encoding="utf-8"))
        cls.safety = {
            name.strip(): value.strip()
            for line in VALIDATOR.SAFETY_BASELINE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
            for name, value in [line.split("=", 1)]
        }

    def assert_rejected(
        self,
        policy: dict[str, Any] | None = None,
        identity: dict[str, Any] | None = None,
        safety: dict[str, str] | None = None,
    ) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(
                copy.deepcopy(policy if policy is not None else self.policy),
                copy.deepcopy(identity if identity is not None else self.identity),
                copy.deepcopy(safety if safety is not None else self.safety),
            )

    def test_unregistered_operation_caller_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        identity["services"] = [
            service for service in identity["services"]
            if service["clientId"] != "codestra-ai"
        ]
        self.assert_rejected(identity=identity)

    def test_missing_operation_scope_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        grant = next(
            item for item in identity["grants"]
            if item["callerClientId"] == "codestra-ai"
            and item["targetClientId"] == "middleware-api"
        )
        grant["scopes"].remove("ai.inference.request")
        self.assert_rejected(identity=identity)

    def test_direct_middleware_provider_grant_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        identity["grants"].append(
            {
                "callerClientId": "middleware-api",
                "targetClientId": "klyrow-gateway",
                "audience": "klyrow-gateway",
                "scopes": ["email.send"],
            }
        )
        self.assert_rejected(identity=identity)

    def test_enabled_or_missing_safety_gate_is_rejected(self) -> None:
        safety = copy.deepcopy(self.safety)
        safety["LIVE_EMAIL_DELIVERY"] = "true"
        self.assert_rejected(safety=safety)
        safety.pop("LIVE_EMAIL_DELIVERY")
        self.assert_rejected(safety=safety)

    def test_noncanonical_issuer_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["authority"]["issuer"] = "https://auth.example.invalid/realms/codestra"
        self.assert_rejected(policy=policy)

    def test_operation_provider_class_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        operation = next(
            item for item in policy["operations"]
            if item["id"] == "communication.sms.request"
        )
        operation["providerClass"] = "email"
        self.assert_rejected(policy=policy)

    def test_operation_command_binding_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        operation = next(
            item for item in policy["operations"]
            if item["id"] == "marketing.campaign.request"
        )
        operation["target"] = "ai-provider"
        self.assert_rejected(policy=policy)

    def test_operation_route_and_scope_swap_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        email = next(item for item in policy["operations"] if item["id"] == "communication.email.request")
        sms = next(item for item in policy["operations"] if item["id"] == "communication.sms.request")
        email["route"], sms["route"] = sms["route"], email["route"]
        email["scope"], sms["scope"] = sms["scope"], email["scope"]
        self.assert_rejected(policy=policy)

    def test_provider_adapter_and_scope_swap_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        advertising = next(item for item in policy["providerAdapters"] if item["providerClass"] == "advertising")
        ai = next(item for item in policy["providerAdapters"] if item["providerClass"] == "ai")
        advertising["adapterClientId"], ai["adapterClientId"] = ai["adapterClientId"], advertising["adapterClientId"]
        advertising["dispatchScope"], ai["dispatchScope"] = ai["dispatchScope"], advertising["dispatchScope"]
        self.assert_rejected(policy=policy)

    def test_missing_readback_scope_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        grant = next(
            item for item in identity["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "telnexa-gateway"
        )
        grant["scopes"].remove("sms.status.read")
        self.assert_rejected(identity=identity)

    def test_missing_social_readback_scope_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        grant = next(
            item for item in identity["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "postly-adapter"
        )
        grant["scopes"].remove("social.status.read")
        self.assert_rejected(identity=identity)

    def test_missing_ai_readback_scope_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        grant = next(
            item for item in identity["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "ai-provider-adapter"
        )
        grant["scopes"].remove("ai.provider.status.read")
        self.assert_rejected(identity=identity)

    def test_missing_marketing_readback_scope_is_rejected(self) -> None:
        identity = copy.deepcopy(self.identity)
        grant = next(
            item for item in identity["grants"]
            if item["callerClientId"] == "middleware-worker"
            and item["targetClientId"] == "marketing-provider-adapter"
        )
        grant["scopes"].remove("marketing.provider.status.read")
        self.assert_rejected(identity=identity)

    def test_non_effect_operation_durability_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        operation = next(
            item for item in policy["operations"]
            if item["id"] == "odoo.event.publish"
        )
        operation["durability"] = "best_effort"
        self.assert_rejected(policy=policy)

    def test_duplicate_provider_class_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        adapter = next(
            item for item in policy["providerAdapters"]
            if item["providerClass"] == "ai"
        )
        policy["providerAdapters"].append(copy.deepcopy(adapter))
        policy["providerAdapters"].sort(key=lambda item: item["providerClass"])
        self.assert_rejected(policy=policy)


if __name__ == "__main__":
    unittest.main()
