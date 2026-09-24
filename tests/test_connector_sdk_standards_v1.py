"""Static interoperability tests for Connector SDK standards artifacts."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ConnectorSdkStandardsArtifactTests(unittest.TestCase):
    def test_cloudevent_schema_uses_json_schema_2020_12(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "contracts/connectors/cloudevent.v1.schema.json"
            ).read_text()
        )
        self.assertEqual(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        self.assertIn("specversion", schema["required"])
        self.assertEqual(
            schema["properties"]["specversion"]["const"],
            "1.0",
        )
        self.assertIn("tenantid", schema["required"])
        self.assertIn("traceparent", schema["properties"])

    def test_openapi_profile_is_311_and_problem_details(self) -> None:
        text = (
            ROOT
            / "contracts/connectors/connector-management-api.v1.yaml"
        ).read_text()
        for marker in (
            "openapi: 3.1.1",
            "jsonSchemaDialect: https://json-schema.org/draft/2020-12/schema",
            "application/problem+json:",
            "ProblemDetails:",
            "traceparent",
            "tracestate",
            "CloudEvents-1.0",
            "RFC9700",
            "./connector-manifest.v1.schema.json",
            "./cloudevent.v1.schema.json",
        ):
            self.assertIn(marker, text)

    def test_storage_binds_version_digest_and_tenant_event_keys(self) -> None:
        text = (
            ROOT
            / "contracts/connectors/connector-storage.v1.sql"
        ).read_text()
        for marker in (
            "UNIQUE (connector_id, version, manifest_digest)",
            "current_manifest_digest",
            "connector_webhook_event_keys",
            "connector_webhook_event_keys_tenant_policy",
            "tenant_resolution",
            "provider-account-mapping",
            "cloud_event jsonb",
            "traceparent text",
            "UNIQUE NULLS NOT DISTINCT",
        ):
            self.assertIn(marker, text)
        self.assertNotIn("UNIQUE (route_path)", text)

    def test_standards_profile_names_normative_baseline(self) -> None:
        text = (
            ROOT
            / "docs/connectors/CONNECTOR_SDK_STANDARDS_PROFILE_V1.md"
        ).read_text()
        for marker in (
            "OpenAPI 3.1.1",
            "JSON Schema Draft 2020-12",
            "CloudEvents 1.0",
            "W3C Trace Context",
            "RFC 9457",
            "RFC 9700",
            "Semantic Versioning 2.0.0",
            "RFC 9421 extension point",
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
