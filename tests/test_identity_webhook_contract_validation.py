from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts import validate_identity_webhook_contracts as validator


ROOT = Path(__file__).resolve().parents[1]
BOUND_FILES = (
    "config/identity-access-map.json",
    "config/api-webhook-contracts.json",
    "config/connectivity-map.json",
    "contracts/beyvra-identity-provisioned.schema.json",
    "contracts/event-envelope.schema.json",
    "contracts/http-conventions.md",
    "contracts/observability-conventions.md",
    "contracts/platform/event-envelope.v1.schema.json",
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class IdentityWebhookContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.contract_root = Path(self.temporary_directory.name)
        for relative in BOUND_FILES:
            destination = self.contract_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def mutate_json(
        self,
        relative: str,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        path = self.contract_root / relative
        value = read_json(path)
        mutation(value)
        write_json(path, value)

    def assert_rejected(self, expected: str) -> None:
        with self.assertRaisesRegex(validator.ContractError, expected):
            validator.validate(self.contract_root)

    def test_current_contract_passes(self) -> None:
        service_count, grant_count, webhook_count, event_count, states = (
            validator.validate(ROOT)
        )
        self.assertEqual(
            (service_count, grant_count, webhook_count, event_count), (18, 32, 8, 40)
        )
        self.assertEqual(sum(states.values()), 18)

    def test_duplicate_json_key_fails_closed(self) -> None:
        path = self.contract_root / "config/identity-access-map.json"
        path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        self.assert_rejected("duplicate key: schemaVersion")

    def test_nonstandard_json_number_fails_closed(self) -> None:
        path = self.contract_root / "config/identity-access-map.json"
        path.write_text('{"schemaVersion":NaN}', encoding="utf-8")
        self.assert_rejected("non-standard JSON constant: NaN")

    def test_access_top_level_alias_field_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access.update(issuerAlias=access["issuer"]),
        )
        self.assert_rejected("identity-access-map.json fields changed")

    def test_boolean_token_lifetime_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access["machineTokenPolicy"].update(
                maximumAccessTokenLifetimeSeconds=True
            ),
        )
        self.assert_rejected("machine access-token lifetime")

    def test_boolean_schema_version_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access.update(schemaVersion=True),
        )
        self.assert_rejected("schemaVersion must be 1")

    def test_service_extra_field_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access["services"][0].update(clientSecret="placeholder"),
        )
        self.assert_rejected(r"services\[0\] has an invalid shape")

    def test_unhashable_grant_identity_fails_as_contract_error(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access["grants"][0].update(callerClientId=[]),
        )
        self.assert_rejected(r"grants\[0\] has an invalid caller")

    def test_malformed_administrative_boundary_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access.update(administrativeBoundaries=[]),
        )
        self.assert_rejected("administrativeBoundaries must be an object")

    def test_webhook_lifecycle_source_drift_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["lifecycleContract"].update(
                protectedBranch="review-branch"
            ),
        )
        self.assert_rejected("webhook lifecycle source must be protected main")

    def test_fabricated_lifecycle_merge_sha_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["lifecycleContract"].update(
                mergeSha="0" * 40
            ),
        )
        self.assert_rejected(
            "webhook lifecycle merge SHA must match approved protected-main authority"
        )

    def test_fabricated_upstream_review_sha_fails_closed(self) -> None:
        self.mutate_json(
            "config/identity-access-map.json",
            lambda access: access["upstreamContract"].update(reviewSha="0" * 40),
        )
        self.assert_rejected(
            "upstream review SHA must match approved source authority"
        )

    def test_malformed_event_schema_required_fields_fail_closed(self) -> None:
        self.mutate_json(
            "contracts/platform/event-envelope.v1.schema.json",
            lambda schema: schema.update(required=[{}]),
        )
        self.assert_rejected("event envelope required fields must be strings")

    def test_loose_event_type_pattern_fails_closed(self) -> None:
        self.mutate_json(
            "contracts/platform/event-envelope.v1.schema.json",
            lambda schema: schema["properties"]["event_type"].update(
                pattern="^codestra.*"
            ),
        )
        self.assert_rejected("event envelope type pattern")

    def test_event_payload_contract_drift_fails_closed(self) -> None:
        self.mutate_json(
            "contracts/platform/event-envelope.v1.schema.json",
            lambda schema: schema["properties"]["payload"].update(
                additionalProperties=False
            ),
        )
        self.assert_rejected("event envelope property contracts changed")

    def test_open_event_envelope_schema_fails_closed(self) -> None:
        self.mutate_json(
            "contracts/platform/event-envelope.v1.schema.json",
            lambda schema: schema.update(additionalProperties=True),
        )
        self.assert_rejected("event envelope must be a closed object schema")

    def test_duplicate_required_header_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["security"]["requiredHeaders"].append(
                "Authorization"
            ),
        )
        self.assert_rejected("webhook required header set changed")

    def test_malformed_required_header_fails_as_contract_error(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["security"].update(requiredHeaders=[{}]),
        )
        self.assert_rejected("webhook required header set changed")

    def test_non_json_webhook_content_type_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["security"].update(contentType="text/plain"),
        )
        self.assert_rejected("webhook content type must be application/json")

    def test_float_clock_skew_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["security"].update(
                maximumClockSkewSeconds=300.0
            ),
        )
        self.assert_rejected("webhook maximum clock skew must be 300 seconds")

    def test_path_traversal_fails_closed(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["webhooks"][0].update(
                path="/api/v1/odoo/../admin"
            ),
        )
        self.assert_rejected(r"webhooks\[0\] has an invalid or duplicate relative path")

    def test_malformed_event_type_fails_as_contract_error(self) -> None:
        self.mutate_json(
            "config/api-webhook-contracts.json",
            lambda webhooks: webhooks["webhooks"][0].update(eventTypes=[{}]),
        )
        self.assert_rejected(r"webhooks\[0\] event types must be sorted and unique")

    def test_malformed_connectivity_policy_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity.update(policies=[]),
        )
        self.assert_rejected("connectivity policies must be an object")

    def test_malformed_workstream_dependencies_fail_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["workstream_dependencies"].update(
                {"platform/kong": {}}
            ),
        )
        self.assert_rejected("platform/kong: dependencies must be unique strings")

    def test_malformed_unused_workstream_dependencies_fail_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["workstream_dependencies"].update(
                {"unbound/workstream": {}}
            ),
        )
        self.assert_rejected("unbound/workstream: dependencies must be unique strings")

    def test_missing_canonical_contract_dependency_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["workstream_dependencies"][
                "integration/odoo-19"
            ].remove("core/integration-contracts"),
        )
        self.assert_rejected(
            "integration/odoo-19 must depend on core/integration-contracts"
        )

    def test_unknown_dependency_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["workstream_dependencies"][
                "integration/odoo-19"
            ].append("platform/unknown"),
        )
        self.assert_rejected("integration/odoo-19 has unknown dependencies")

    def test_connection_without_authentication_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["connections"][0].update(
                authentication="none"
            ),
        )
        self.assert_rejected(r"connections\[0\] requires explicit authentication")

    def test_unknown_connection_transport_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["connections"][0].update(
                transport="httpss"
            ),
        )
        self.assert_rejected(r"connections\[0\] has an invalid transport")

    def test_connection_unknown_workstream_fails_closed(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["connections"][0].update(
                target_branch="platform/unknown"
            ),
        )
        self.assert_rejected(r"connections\[0\] references an unknown workstream")

    def test_malformed_connection_runtime_status_fails_as_contract_error(self) -> None:
        self.mutate_json(
            "config/connectivity-map.json",
            lambda connectivity: connectivity["connections"][0].update(
                runtime_status=[]
            ),
        )
        self.assert_rejected(r"connections\[0\] has an unverified runtime status")

    def test_missing_connection_contract_fails_closed(self) -> None:
        (self.contract_root / "contracts/http-conventions.md").unlink()
        self.assert_rejected(r"connections\[0\] references a missing contract")


if __name__ == "__main__":
    unittest.main()
