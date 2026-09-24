from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts import validate_postal_domain_registry as validator


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class PostalDomainRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.contract_root = Path(self.temporary_directory.name)
        destination = self.contract_root / "config"
        destination.mkdir()
        for name in (
            "postal-domain-registry.json",
            "preproduction-safety.env.example",
        ):
            shutil.copyfile(ROOT / "config" / name, destination / name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @property
    def registry_path(self) -> Path:
        return self.contract_root / "config/postal-domain-registry.json"

    @property
    def safety_path(self) -> Path:
        return self.contract_root / "config/preproduction-safety.env.example"

    def mutate_registry(self, mutation: Callable[[dict[str, Any]], None]) -> None:
        registry = read_json(self.registry_path)
        mutation(registry)
        write_json(self.registry_path, registry)

    def assert_rejected(self, expected: str) -> None:
        with self.assertRaisesRegex(SystemExit, expected):
            validator.validate(self.contract_root)

    def test_current_registry_passes(self) -> None:
        self.assertEqual(validator.validate(ROOT), (15, 14, 1))

    def test_duplicate_json_key_fails_closed(self) -> None:
        self.registry_path.write_text('{"version":1,"version":1}', encoding="utf-8")
        self.assert_rejected("invalid_json:postal-domain-registry.json")

    def test_nonstandard_json_number_fails_closed(self) -> None:
        self.registry_path.write_text('{"version":NaN}', encoding="utf-8")
        self.assert_rejected("invalid_json:postal-domain-registry.json")

    def test_non_object_evidence_fails_closed(self) -> None:
        self.mutate_registry(lambda registry: registry.update(evidence=[]))
        self.assert_rejected("invalid_evidence")

    def test_unknown_registry_field_fails_closed(self) -> None:
        self.mutate_registry(lambda registry: registry.update(unreviewed=True))
        self.assert_rejected("registry_fields_changed")

    def test_non_object_domain_fails_closed(self) -> None:
        self.mutate_registry(lambda registry: registry["domains"].append([]))
        self.assert_rejected("invalid_domain_entry")

    def test_non_string_domain_fails_closed(self) -> None:
        self.mutate_registry(lambda registry: registry["domains"][0].update(domain=[]))
        self.assert_rejected("invalid_domain_name")

    def test_case_variant_domain_fails_closed(self) -> None:
        self.mutate_registry(
            lambda registry: registry["domains"][0].update(domain="BEYVRA.COM")
        )
        self.assert_rejected("invalid_domain_name:BEYVRA.COM")

    def test_duplicate_domain_fails_closed(self) -> None:
        self.mutate_registry(
            lambda registry: registry["domains"].append(registry["domains"][0].copy())
        )
        self.assert_rejected("duplicate_domain:beyvra.com")

    def test_boolean_policy_does_not_accept_integer_fails_closed(self) -> None:
        self.mutate_registry(
            lambda registry: registry["policies"].update(
                middleware_is_domain_authority=1
            )
        )
        self.assert_rejected("policy_must_be_true:middleware_is_domain_authority")

    def test_eligibility_prerequisite_drift_fails_closed(self) -> None:
        self.mutate_registry(
            lambda registry: registry["policies"]["send_eligibility_requires"].pop()
        )
        self.assert_rejected("send_eligibility_requirements_changed")

    def test_lowercase_private_key_marker_fails_closed(self) -> None:
        self.mutate_registry(
            lambda registry: registry.update(
                workstream="integration/begin openssh private key"
            )
        )
        self.assert_rejected("forbidden_secret_marker:begin openssh private key")

    def test_duplicate_safety_flag_fails_closed(self) -> None:
        with self.safety_path.open("a", encoding="utf-8") as safety_file:
            safety_file.write("\nEMAIL_DELIVERY_ENABLED=true\n")
        self.assert_rejected("duplicate_safety_flag:EMAIL_DELIVERY_ENABLED")

    def test_credential_shaped_safety_variable_fails_closed(self) -> None:
        names = (
            "POSTAL_ACCESS_KEY",
            "POSTAL_API_KEY",
            "POSTAL_CREDENTIAL",
            "POSTAL_API_TOKEN",
        )
        for name in names:
            with self.subTest(name=name):
                shutil.copyfile(
                    ROOT / "config/preproduction-safety.env.example",
                    self.safety_path,
                )
                with self.safety_path.open("a", encoding="utf-8") as safety_file:
                    safety_file.write(f"\n{name}=placeholder\n")
                self.assert_rejected(f"forbidden_safety_secret_name:{name}")

    def test_enabled_delivery_alias_fails_closed(self) -> None:
        with self.safety_path.open("a", encoding="utf-8") as safety_file:
            safety_file.write("\nCUSTOM_EMAIL_DELIVERY_GATE=true\n")
        self.assert_rejected("enabled_delivery_alias:CUSTOM_EMAIL_DELIVERY_GATE")

    def test_live_email_alias_must_be_explicitly_disabled(self) -> None:
        safety = self.safety_path.read_text(encoding="utf-8")
        self.safety_path.write_text(
            safety.replace("ALLOW_LIVE_EMAIL=false", "ALLOW_LIVE_EMAIL=true"),
            encoding="utf-8",
        )
        self.assert_rejected("enabled_delivery_alias:ALLOW_LIVE_EMAIL")

    def test_control_character_in_safety_value_fails_closed(self) -> None:
        with self.safety_path.open("a", encoding="utf-8") as safety_file:
            safety_file.write("\nAPP_NOTE=value\x00junk\n")
        self.assert_rejected("invalid_safety_control_character:APP_NOTE")

    def test_enabled_safety_flag_fails_closed(self) -> None:
        safety = self.safety_path.read_text(encoding="utf-8")
        self.safety_path.write_text(
            safety.replace("LIVE_EMAIL_DELIVERY=false", "LIVE_EMAIL_DELIVERY=true"),
            encoding="utf-8",
        )
        self.assert_rejected("enabled_delivery_alias:LIVE_EMAIL_DELIVERY")


if __name__ == "__main__":
    unittest.main()
