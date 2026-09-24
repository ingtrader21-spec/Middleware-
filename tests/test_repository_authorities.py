from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts import validate_repository_authorities as validator


ROOT = Path(__file__).resolve().parents[1]
POLICY_DOCUMENTS = (
    Path("README.md"),
    Path("docs/CI-ENVIRONMENTS-AND-HANDOFF.md"),
    Path("docs/REPOSITORY-AUTHORITY-POLICY.md"),
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class RepositoryAuthorityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.contract_root = Path(self.temporary_directory.name)
        for relative in (
            Path("config/repository-authorities.v1.json"),
            Path("config/adapter-registry.v2.json"),
            *POLICY_DOCUMENTS,
        ):
            destination = self.contract_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        shutil.copytree(
            ROOT / "connectors/manifests",
            self.contract_root / "connectors/manifests",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def assert_rejected(self, expected: str) -> None:
        with self.assertRaisesRegex(SystemExit, expected):
            validator.validate(self.contract_root)

    def mutate_json(
        self,
        relative: str,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        path = self.contract_root / relative
        data = read_json(path)
        mutation(data)
        write_json(path, data)

    def test_repository_authority_contract_is_complete(self) -> None:
        self.assertEqual(validator.validate(ROOT), (33, 11))

    def test_duplicate_authority_component_fails_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["authorities"].append(data["authorities"][0].copy()),
        )
        self.assert_rejected("duplicate_component")

    def test_duplicate_principal_repository_fails_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["authorities"][1].update(
                principal_repository=data["authorities"][0]["principal_repository"]
            ),
        )
        self.assert_rejected("duplicate_principal_repository")

    def test_case_variant_principal_repository_fails_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["authorities"][1].update(
                principal_repository=data["authorities"][0][
                    "principal_repository"
                ].lower()
            ),
        )
        self.assert_rejected("duplicate_principal_repository")

    def test_malformed_principal_repository_fails_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["authorities"][0].update(
                principal_repository="appolon1908-hue/nested/repository"
            ),
        )
        self.assert_rejected("invalid_authority_identity")

    def test_case_variant_reference_repository_fails_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["authorities"].append(
                {
                    "component": "reference-alias",
                    "principal_repository": (
                        "appolon1908-hue/CODESTRA-PRODUCTION-PLATFORM"
                    ),
                    "role": "forbidden-reference-alias",
                }
            ),
        )
        self.assert_rejected("reference_repo_cannot_be_principal:reference-alias")

    def test_scalar_reference_uses_fail_closed(self) -> None:
        self.mutate_json(
            "config/repository-authorities.v1.json",
            lambda data: data["reference_only"][0].update(allowed_uses="evidence"),
        )
        self.assert_rejected("reference_allowed_uses_invalid")

    def test_direct_n8n_adapter_fails_closed(self) -> None:
        self.mutate_json(
            "config/adapter-registry.v2.json",
            lambda data: data["adapters"][0].update(direct_n8n=True),
        )
        self.assert_rejected("direct_n8n_forbidden:ai-provider")

    def test_unregistered_adapter_repository_fails_closed(self) -> None:
        self.mutate_json(
            "config/adapter-registry.v2.json",
            lambda data: data["adapters"][0].update(
                repository="appolon1908-hue/unregistered"
            ),
        )
        self.assert_rejected("adapter_repository_has_no_principal:ai-provider")

    def test_duplicate_adapter_id_fails_closed(self) -> None:
        self.mutate_json(
            "config/adapter-registry.v2.json",
            lambda data: data["adapters"].append(data["adapters"][0].copy()),
        )
        self.assert_rejected("duplicate_adapter_id:ai-provider")

    def test_manifest_repository_drift_fails_closed(self) -> None:
        self.mutate_json(
            "connectors/manifests/ai-provider.connector.json",
            lambda data: data.update(repository="appolon1908-hue/Codestra-Marketing-"),
        )
        self.assert_rejected("connector_repository_drift:ai-provider")

    def test_manifest_filename_drift_fails_closed(self) -> None:
        source = self.contract_root / "connectors/manifests/ai-provider.connector.json"
        source.rename(source.with_name("renamed.connector.json"))
        self.assert_rejected("connector_filename_drift:renamed.connector.json")

    def test_missing_manifest_fails_closed(self) -> None:
        (
            self.contract_root / "connectors/manifests/ai-provider.connector.json"
        ).unlink()
        self.assert_rejected("connector_manifest_inventory_changed")

    def test_noncanonical_json_fails_closed(self) -> None:
        contents = (
            '{"schema_version":"1.0","schema_version":"1.0"}',
            '{"schema_version":NaN}',
        )
        for content in contents:
            with self.subTest(content=content):
                path = self.contract_root / "config/repository-authorities.v1.json"
                path.write_text(content, encoding="utf-8")
                self.assert_rejected("invalid_json:repository-authorities.v1.json")


if __name__ == "__main__":
    unittest.main()
