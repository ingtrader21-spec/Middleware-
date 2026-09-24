"""Deployment regression checks for private proxy health-check children."""

from pathlib import Path
import unittest

import yaml  # type: ignore[import-untyped]  # PyYAML is pinned without type stubs.


ROOT = Path(__file__).resolve().parents[1]
PROXIES = (
    ("deploy/internal-odoo/compose.internal-odoo.yaml", "odoo-internal-proxy"),
    ("deploy/internal-n8n-private/compose.internal-n8n.yaml", "n8n-internal-proxy"),
)


class InternalProxyProcessLifecycleTests(unittest.TestCase):
    def services(self):
        for path, name in PROXIES:
            document = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
            yield name, document["services"][name]

    def test_orphaned_healthcheck_children_have_an_init_reaper(self):
        for name, service in self.services():
            with self.subTest(service=name):
                self.assertIs(service.get("init"), True)

    def test_process_growth_is_bounded(self):
        for name, service in self.services():
            with self.subTest(service=name):
                limit = service.get("pids_limit")
                self.assertIs(type(limit), int)
                self.assertGreaterEqual(limit, 64)
                self.assertLessEqual(limit, 256)

    def test_reaping_preserves_private_tls_and_container_restrictions(self):
        for name, service in self.services():
            with self.subTest(service=name):
                self.assertIs(service["read_only"], True)
                self.assertEqual(service["cap_drop"], ["ALL"])
                self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
                self.assertFalse(service.get("privileged", False))
                self.assertFalse(service.get("ports"))
                self.assertNotEqual(service.get("pid"), "host")
                self.assertNotEqual(service.get("network_mode"), "host")
                health = " ".join(service["healthcheck"]["test"])
                self.assertIn("SSL_CERT_FILE=/run/secrets/internal_integration_ca", health)
                self.assertIn("https://", health)
                self.assertNotIn("--no-check-certificate", health)
                self.assertTrue(all(mount.endswith(":ro") for mount in service["volumes"]))


if __name__ == "__main__":
    unittest.main()
