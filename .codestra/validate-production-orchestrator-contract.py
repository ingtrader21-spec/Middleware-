#!/usr/bin/env python3
"""Fail-closed validation for the repository-owned production contract."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / ".codestra/production-orchestrator-contract.v1.json"
INTENT_PATH = ROOT / ".github/workflows/manual-release-intent.yml"
RELEASE_VALIDATOR_PATH = ROOT / ".codestra/validate-release-intent.py"
RELEASE_VALIDATOR_NON_SELF_REFERENTIAL_BINDINGS = frozenset(
    {
        "SHARED_PRODUCTION_VALIDATOR_SHA256",
        "KEYCLOAK_PRODUCTION_VALIDATOR_SHA256",
        "MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256",
        "BACKEND_PRODUCTION_VALIDATOR_SHA256",
        "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256",
    }
)
STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256 = (
    "15dbaa6d571a1d1e72c09ca417cc9419"
    "8d8f21260babfae5eaedbdd46472b1ec"
)
MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256 = (
    "e3b70953e9fac5ba4e8dbe696241a8057be2cf530bb0e782fe83d3a268e820b0"
)
BACKEND_RELEASE_VALIDATOR_SECURITY_SHA256 = (
    "15dbaa6d571a1d1e72c09ca417cc9419"
    "8d8f21260babfae5eaedbdd46472b1ec"
)
MONEYBEE_RELEASE_VALIDATOR_SECURITY_SHA256 = (
    "15dbaa6d571a1d1e72c09ca417cc9419"
    "8d8f21260babfae5eaedbdd46472b1ec"
)
EXPECTED_RELEASE_VALIDATOR_SECURITY_SHA256 = {
    "appolon1908-hue/Infustruction-repo": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/Keycloak": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "ingtrader21-spec/Middleware-": MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/codestra": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/beyvra-backend": BACKEND_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/backend2": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/beyvra-frontend": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/scrapper": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/Breero.com": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/Moneybee-Backend": MONEYBEE_RELEASE_VALIDATOR_SECURITY_SHA256,
    "appolon1908-hue/Telnexa-web": STANDARD_RELEASE_VALIDATOR_SECURITY_SHA256,
}
MANUAL_RELEASE_INTENT_SHA256 = (
    "3053a509c4292f08495c0277e29879a60ca06de7fee94c44a2e26977e2441d51"
)
SCHEMA = "codestra.production-orchestrator-contract.v1"
PHASES = ["plan", "staging", "canary", "production"]
SAFETY_KEYS = {
    "external_effects_default",
    "live_email_delivery",
    "live_sms_delivery",
    "live_pstn_dialing",
    "odoo_write",
    "n8n_external_delivery",
    "live_trading",
    "payment_execution",
}
ALLOWED_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
}
PINNED_WORKFLOW_PARSER_INSTALL = (
    "python3 -m pip install --disable-pip-version-check --no-input PyYAML==6.0.3"
)
RUNTIME_TOOLS = {
    "ansible-playbook",
    "chroot",
    "docker",
    "helm",
    "kubectl",
    "podman",
    "scp",
    "script",
    "ssh",
    "terraform",
    "tofu",
}
SHELL_INTERPRETERS = {"bash", "dash", "eval", "ksh", "sh", "zsh"}
SCRIPT_INTERPRETERS = {"node", "perl", "php", "python", "python3", "ruby"}
SAFE_EXTERNAL_PYTHON_MODULES = {
    "compileall",
    "http.server",
    "json.tool",
    "pip",
    "py_compile",
    "pytest",
    "ruff",
    "unittest",
    "venv",
}
EXECUTABLE_STARTUP_ENV = {
    "BASH_ENV",
    "ENV",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PATH",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
}
SHELL_WRAPPERS = {
    "!",
    "builtin",
    "command",
    "chrt",
    "env",
    "exec",
    "flock",
    "ionice",
    "nice",
    "nohup",
    "parallel",
    "run-parts",
    "setpriv",
    "setsid",
    "sg",
    "stdbuf",
    "su",
    "sudo",
    "systemd-run",
    "taskset",
    "time",
    "timeout",
    "prlimit",
    "unshare",
    "watch",
}
SHELL_SEPARATORS = {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}
GENERIC_NETWORK_CLIENTS = {
    "curl",
    "ftp",
    "lftp",
    "nc",
    "ncat",
    "netcat",
    "sftp",
    "socat",
    "telnet",
    "wget",
}
RELEASE_INTENT_ALLOWED_COMMANDS = {
    "base64",
    "cut",
    "gh",
    "jq",
    "printf",
    "python3",
    "set",
    "sha256sum",
    "test",
    "umask",
}
RELEASE_INTENT_ALLOWED_GH_API = {
    (
        "api",
        "repos/${GITHUB_REPOSITORY}",
        "--jq",
        ".default_branch",
    ),
    (
        "api",
        "repos/${GITHUB_REPOSITORY}/branches/${branch}",
        "--jq",
        ".commit.sha",
    ),
}
KUBECTL_MUTATIONS = {
    "annotate",
    "apply",
    "autoscale",
    "cordon",
    "cp",
    "create",
    "delete",
    "debug",
    "drain",
    "edit",
    "exec",
    "expose",
    "label",
    "patch",
    "replace",
    "rollout",
    "run",
    "scale",
    "set",
    "taint",
    "uncordon",
}
HELM_MUTATIONS = {"install", "rollback", "uninstall", "upgrade"}
TERRAFORM_MUTATIONS = {"apply", "destroy", "import", "taint", "untaint"}
CONTAINER_MUTATIONS = {"down", "kill", "rm", "start", "stop", "restart", "up"}
HTTP_MUTATION_FLAGS = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--json",
    "--upload-file",
    "-d",
}
HTTP_MUTATION_METHODS = {"delete", "patch", "post", "put"}
NETWORK_MUTATION_METHODS = {
    "connect",
    "connect_ex",
    "delete",
    "endheaders",
    "mkd",
    "patch",
    "post",
    "put",
    "putrequest",
    "rename",
    "rmd",
    "send",
    "sendfile",
    "sendmsg",
    "send_message",
    "sendall",
    "sendto",
    "sendmail",
    "sendcmd",
    "storbinary",
    "storlines",
    "voidcmd",
    "write",
    "writelines",
}
NETWORK_CLIENT_HINTS = {
    "aiohttp",
    "api",
    "api_client",
    "client",
    "connection",
    "ftp",
    "ftplib",
    "http",
    "http_client",
    "httpx",
    "requests",
    "session",
    "smtp",
    "smtplib",
    "sock",
    "socket",
    "urllib3",
}
DATABASE_MUTATION_METHODS = {
    "add",
    "bulk_write",
    "bulk_insert_mappings",
    "bulk_save_objects",
    "commit",
    "create",
    "delete",
    "delete_many",
    "delete_one",
    "executemany",
    "flush",
    "find_one_and_delete",
    "find_one_and_replace",
    "find_one_and_update",
    "insert",
    "insert_many",
    "insert_one",
    "save",
    "update",
    "update_many",
    "update_one",
    "upsert",
    "replace_one",
}
DATABASE_CLIENT_HINTS = {
    "asyncpg",
    "conn",
    "connection",
    "cursor",
    "database",
    "db",
    "engine",
    "mongo",
    "mongodb",
    "psycopg",
    "psycopg2",
    "pymongo",
    "pymysql",
    "session",
    "sqlalchemy",
}
SCRIPT_SUFFIXES = {".bash", ".cjs", ".js", ".mjs", ".php", ".pl", ".py", ".rb", ".sh"}
SQL_MUTATION = re.compile(
    r"\b(?:alter|create|delete|drop|grant|insert|merge|revoke|truncate|update)\b",
    re.IGNORECASE,
)
MUTATING_ACTION_MARKERS = {
    "ansible",
    "cloudformation",
    "deploy",
    "helm",
    "kubectl",
    "kubernetes",
    "scp",
    "ssh",
    "terraform",
}
SAFE_NATIVE_ACTION_PREFIXES = {
    "actions/attest-build-provenance@",
    "actions/attest@",
    "actions/cache@",
    "actions/checkout@",
    "actions/download-artifact@",
    "actions/setup-node@",
    "actions/setup-python@",
    "actions/upload-artifact@",
    "anchore/sbom-action@",
    "anchore/scan-action@",
    "aquasecurity/setup-trivy@",
    "aquasecurity/trivy-action@",
    "docker/build-push-action@",
    "docker/login-action@",
    "docker/setup-buildx-action@",
    "github/codeql-action/",
    "gitleaks/gitleaks-action@",
    "pnpm/action-setup@",
    "pypa/gh-action-pip-audit@",
    "sigstore/cosign-installer@",
}
EXPECTED_IDENTITIES: dict[str, tuple[int, str, bool, bool]] = {
    "appolon1908-hue/Infustruction-repo": (1350724865, "infrastructure", True, True),
    "appolon1908-hue/Keycloak": (1347523366, "identity", True, False),
    "ingtrader21-spec/Middleware-": (1347559071, "canonical-middleware", False, False),
    "appolon1908-hue/codestra": (1319808791, "application", True, False),
    "appolon1908-hue/beyvra-backend": (1319831182, "application", True, False),
    "appolon1908-hue/backend2": (1319903950, "application", True, False),
    "appolon1908-hue/beyvra-frontend": (1320246591, "application", True, False),
    "appolon1908-hue/scrapper": (1329513537, "migration-evidence", False, False),
    "appolon1908-hue/Breero.com": (1331354808, "application", True, False),
    "appolon1908-hue/Moneybee-Backend": (1343760409, "application", True, False),
    "appolon1908-hue/Telnexa-web": (1346958528, "application", True, False),
    "appolon1908-hue/codestra-production-platform": (1314230781, "controller", False, False),
}
EXPECTED_ARTIFACT_POLICIES: dict[
    str, tuple[tuple[str, ...], bool, bool, bool, str | None, str | None]
] = {
    "appolon1908-hue/Infustruction-repo": ((), False, False, False, None, None),
    "appolon1908-hue/Keycloak": ((), False, False, False, None, None),
    "ingtrader21-spec/Middleware-": (
        ("ghcr.io/ingtrader21-spec/codestra-middleware",),
        True,
        True,
        True,
        "cosign",
        "oci",
    ),
    "appolon1908-hue/codestra": (
        ("ghcr.io/appolon1908-hue/codestra",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-backend": (
        (
            "ghcr.io/appolon1908-hue/beyvra-backend",
            "ghcr.io/appolon1908-hue/beyvra-backend-edge",
        ),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/backend2": (
        ("ghcr.io/appolon1908-hue/backend2",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-frontend": (
        ("ghcr.io/appolon1908-hue/beyvra-frontend",),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/scrapper": ((), False, False, False, None, None),
    "appolon1908-hue/Breero.com": (
        (
            "ghcr.io/appolon1908-hue/breero-api",
            "ghcr.io/appolon1908-hue/breero-frontend",
            "ghcr.io/appolon1908-hue/breero-partner",
            "ghcr.io/appolon1908-hue/breero-ops",
            "ghcr.io/appolon1908-hue/breero-admin",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Moneybee-Backend": (
        (
            "ghcr.io/appolon1908-hue/moneybee-api",
            "ghcr.io/appolon1908-hue/moneybee-worker",
            "ghcr.io/appolon1908-hue/moneybee-migrate",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Telnexa-web": (
        ("ghcr.io/appolon1908-hue/telnexa-web",),
        True,
        True,
        False,
        "github",
        "github",
    ),
}
APPROVED_COMPLEX_SCRIPT_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Keycloak": {
        "scripts/ci/audit_keycloak_pull_requests.py": "fa0c559a3dccfd4ced2a73ebcb2e1858724dcdba654fe84198045a6abbfc358b",
        "tests/test_audit_keycloak_pull_requests.py": "0d1065ef132a324ab52694c61e2f47c24fa0787e1a92334f6d34ba0f9b952325",
        "scripts/bootstrap_release_trust_root.py": "265c4d1b9bd365d0cb14d933ec4fa22a269295952874781413befd87a241a294",
        "scripts/review-plan.sh": "65fe10f82d6fdb51ebca45e0453d5288baf05fa78ddce8754946e702432b50c4",
        "scripts/runtime-preflight.sh": "67bff10567f1c9763794f17d378f1dc3785e18569bda7432d0003d872239a052",
        "scripts/runner-systemd-preflight.sh": "d49eec2b037067dbede30aac8b49328025189e6a8883b0b4314ce613a7bd37be",
        "scripts/test-backup-contract.sh": "48ac288ce0e2eb29f220b5e701ef6a11a5a6cfe3eb058c89ac74b505d3c62d62",
        "scripts/test-ephemeral-docker-auth.sh": (
            "44ed657edf1d82b7aa1d2508d75955ae"
            "30b71399c30055db198e2ea8a62ca277"
        ),
        "scripts/test-plan-gate.sh": "a1998a4a92a2535aea09f35c5de369f0675ab4276e86ab92a42f908590c0ca6d",
        "scripts/test-runtime-preflight.sh": "e4fae06b294f0385d6006d35107463eaa65ec1099fae45ef032dffa1d3f65471",
        "scripts/validate-governance.sh": "8e2fb48c36e849f61c838699726e29a6a57ba5d73e6c6e8048737b1627ec5823",
        "scripts/validate-workflows.py": (
            "946687f92f5f437c3b2beebd3bc3e4b0"
            "2e494375846f03c0f9c8ee9a7b88fd80"
        ),
        "scripts/validate.sh": "3783706062b23eb83b6323aae3be9d5b568de57eac81e3d557cca8c13bba2ace",
    },
    "ingtrader21-spec/Middleware-": {
        "scripts/apply_portfolio_release_reviewer_access.py": (
            "f34213e61c3eba4ac1a9191883421ad3e408c35cba4c91f9fda09e09ffe75d10"
        ),
        "scripts/integration_ci.sh": "8d9327fd9ad51d6ba7243d051336f623a4f75d60c60e69fd012e65f598b12d4a",
        "scripts/validate_middleware_authority_convergence.py": (
            "fd1f54c2f85567aa1cf776b159cc1660"
            "8041950152c41341eeada6bd2e666be8"
        ),
        "scripts/validate-order-orchestration.py": (
            "a9d3688d3175661f54d86d113c8e03fa"
            "74bf96a7db3813e00f5e5cd5be40b2e8"
        ),
        "scripts/nats_integration_ci.sh": "88d843c665cece68e0fb56a931c295ee10490446cad7b64d9f5356c1cbf7263d",
        "scripts/project_ci.sh": "12a529ea96f39baec5f1eeb287209dc9db355e5dca000cbbfd7494303501b2ae",
        "scripts/release_manifest.py": "e93efd297624edca35658eeec0c83e471149c3ce4fe713cf41a26e470f8eb8c2",
        "scripts/run_ci.sh": "64d7c92279dd442144c7e1f74c3e48f0ab5d5db105238a534dcf8ccd99e93138",
        "scripts/synthetic_acceptance_ci.sh": "087dac2c5371f2013fa0a8dd22ed4024409ab5015231fb8801c75cf3203e3a8a",
        "scripts/temporal_integration_ci.sh": "76a682cc1f5b15a0a3eb15a029d87206238dfe4a262eaf5fa2c79403f147d4d6",
        "scripts/verify_container_image.sh": (
            "86550c26b32862fefaf2cefdefa2db1e"
            "73abcb702d28536816f9093df47c5ccd"
        ),
        "services/connector-runtime/scripts/test_postgres.sh": "b9b31391d7a04aa8b3362e182a43f880e46f9e85b4d2f5c3c66cb9a9fe88f867",
        "tests/integration/campaign_extension_concurrency.py": "5699be2ee6b9af5a2aed7d39c68086bc09dc9764e8ed8ffb063ec20fd6aea86a",
        "tests/integration/campaign_identity_concurrency.py": "234d97cf48cf29f0ec26bd4cfd48f61d031f46e1250cee477088abb7a190be76",
        "tests/test_calling_api.py": (
            "9e09c6fcda80a97ac2988f73a5be9ec6"
            "caebd3d812220edba3ebfaf3e4b10902"
        ),
        "tests/test_calling_contract.py": (
            "b8e1f705cfc175348ba6455879f42f78"
            "74e52948786f71fb4a9103e13bc072a7"
        ),
        "tests/test_calling_postgres.py": (
            "49891b89afde1955f66a411facb59fa19"
            "f0c81e17c4e492d45aacf625af2e84e"
        ),
        "tests/test_reconciliation_activity.py": (
            "9573de3bf0b5ad457d6c0673dfc27e53"
            "05746161f11df7b2aa330d196bf8f1b3"
        ),
        "tests/test_vicidial_internal_call_adapter.py": (
            "7d15e3fbd540c8e129062e9b870cfa90"
            "f965d8c98ef3a846b52188c39ab22f99"
        ),
        "tests/pairing/test_selected_server_b.py": (
            "2d30e63fef9c9621a2082418ac22ab8e"
            "30eee34a9b0d17312314822a15185b93"
        ),
        "tests/recording/test_api_contract.py": (
            "9aff153756e954091ac21d2831028a06e"
            "00d42fd24b31343c18695a7193fb66a"
        ),
        "tests/recording/test_odoo_hmac.py": (
            "8f02f5b50fc3728c3f9c1a94e77ca48"
            "d01a19dbfdea38fc4805978bc7824a998"
        ),
        "tests/recording/test_source_gates.py": (
            "b9c11f169acc87d720764ccb580561988"
            "5cf3fa126d86b925d3a8412fd806b3a"
        ),
    },
    "appolon1908-hue/codestra": {
        "scripts/deploy/read-only-runtime-discovery.sh": "14cd8ce2653da1e284da480408ba071fd989279ba889a22d0b1f21ec887e1d13",
        "scripts/ci/check-runtime-discovery.mjs": "a0ccd39eb918093ba7715c9fc40fc9facaef6feef95210c46e9fead61323708f",
        "scripts/ci/test-runtime-discovery-fixture.sh": "a7b6557ed6dc927f6dc78a45440c3cf8deda6a2410a3bf94c70231be3bda751d",
        "scripts/ci/test-runtime-discovery-host-proxy.sh": "c934ec0ff3aa97a08940c0475139edfa155fb839b43017a5a881ffde480ac9e9",
    },
    "appolon1908-hue/beyvra-frontend": {
        "client-portal/scripts/audit-gate.mjs": (
            "8f50a0920735449fe65aa988cf2f4f290"
            "aa744362bbc848830992da7752e2fd6"
        ),
        "client-portal/scripts/check-api-contract.mjs": (
            "df9cf9d60aab7c8296008f4356084610"
            "ebc7ce5430600068d8112e86a6095f30"
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        "FX/release-init-prod.sh": "cef5fadd788f5ae5c9ba28a857bfe516e47b671e36aafcf3817b4c20b9e5115b",
        "operations/verify_release_identity.py": "8aadfc14fa376ba46483216c6323d589d4603c71d42f5a77c29286edb5b5cf0a",
        "scripts/certify_staging_api.py": (
            "a154c1bcd011c42442263d06b530e243"
            "901ec8487c6b34f032e53810f12a5a30"
        ),
    },
    "appolon1908-hue/scrapper": {
        "apps/operations-dashboard/test/api-client.test.mjs": (
            "430b330930d546cdc5270b6d3ffe10955"
            "0e9e725d646e737a54c2654d92b7646"
        ),
        "scripts/validate-gateway.sh": "d0c9888cc7bde27682a32d00fcb00d55d0ff6fc3ad711650cb6647f9dfccdc2a",
        "scripts/validate-deployment-scaffolding.sh": "03db69454e0ea0f62923ab43307ce95ab08c3586d3eb455f53552b65e052cfb9",
        "scripts/validate-workflow-policy.rb": "5cfa66e2126849121a263e0d651b5885ae0535156fb45c47a3ec5f1ca8f587c0",
        "scripts/verify-release-context.sh": "7f1799aed294208d9ad3d86d7f6d246ebf9293ab75fd8df8c16a076f86f9e7ba",
        "test/integration-delivery-replay.test.mjs": (
            "c251545621b2c4a3706ee70b5c376cbc"
            "61f83135f2ab3c56a10ddbef394e55b1"
        ),
        "test/integration-runtime.test.mjs": (
            "57acccbee1522daa07b513a23a212bc7"
            "62353ef1d0998cbbe1fe603927b56697"
        ),
        "test/unit-discovery-import.test.mjs": (
            "9fd2939f0fba91d88e47b2acb76cdc53"
            "360a428172c050d94dacc5a174737a86"
        ),
        "test/unit-document-governance.test.mjs": (
            "7b4d7d5d9e5d5cd383bff5a18c72387d"
            "13c356af729efb6fab331828898d8f08"
        ),
        "test/unit-gateway-routes.test.mjs": (
            "012e916599563c9363e073d0268551ba"
            "31e3a6f77223f631c5556defd811c5be"
        ),
        "test/unit-job-view.test.mjs": (
            "1f20f7c1d6e6051c3f77e173216f850a"
            "b0d77526c256e3285a02d948142251e1"
        ),
        "test/unit-schema.test.mjs": (
            "84e894c7980a53b5295ab66933758fd1"
            "06e6c6c9705c4c6339a462da5b6691db"
        ),
        "test/unit-url-policy.test.mjs": (
            "5218de57f97201b47e51e10943151037"
            "b93ba8b7b883c5ed1462578f76a44849"
        ),
    },
    "appolon1908-hue/Breero.com": {
        "apps/api/scripts/check_schema_drift.py": "746760dea22319cd64c486a08b82ebbccee1dc256566fa6b24cee7f02ff68b47",
        "apps/api/scripts/generate_openapi.py": "7e1ad9606a113b556752222b2782da01b66651b2f8107d3108014b9d45f29a66",
        "scripts/ci/test-classify-quality-scope.sh": "0365cd71d85e00facf1a64c2f11734e413430af75e4cf39e0e52971d13d5c473",
        "scripts/ci/test-validate-breero-scope.sh": "ea29de36868e28ff82e3ec151f896aed388d2421f5907151c4c13480dae20bf8",
        "scripts/ci/validate-breero-scope.sh": "f8ffb8a3953c56d7d6722938825bfb33fced802ba162f4cefd3d12be8ffb9a1e",
    },
    "appolon1908-hue/Moneybee-Backend": {
        "scripts/generate_endpoint_catalog.py": (
            "174a22ef99c72a9432ede92e1c5117e7"
            "092aaf2f9e6dbf40af79087503c30f0a"
        ),
        "ops/stage-bank-credential-references.py": (
            "ea78c91ccc0d779260b13ccead92ca31"
            "16b5b0ac5f3ede028e86a8aa197e3cca"
        ),
        "ops/verify-compose-contract.py": "5b9c78f82de3784af3d68945be43abadbbe3eab7e73f3edf0f27ef7042e7e674",
        "scripts/smoke_api.py": (
            "62b60fa9fb0331d5227b51b9b2c542d"
            "4ec96da9f683a5f678a60d5f27996c692"
        ),
        "scripts/verify_openapi_contract.py": (
            "b4dd40045e2781a6a741787b0c1a51d"
            "30b96248027a0e058f0123a9853a784a0"
        ),
    },
    "appolon1908-hue/Telnexa-web": {
        "deployment/scripts/validate-compliance.sh": "a29fa2c3586332016ec468a710487bca7e5362244c6feec63ae1bde47f4f0f75",
        "scripts/smoke-local.mjs": "13d7f9fcd9bdcc1ac598018a0ca2aab3b3478c08d845b3d0f366b533e4142313",
        "scripts/validate-compliance.mjs": "cd174eebb976c8995545ceb07cd761e53ff1a54ac30c2a4b015bbd92a0768306",
        "scripts/validate-contracts.mjs": (
            "d1fa0b7327863cfcfcf3d00cbc275b45"
            "5155efbd2e54f35589e4b4f6b9b3f162"
        ),
        "tests/contracts/compliance.test.mjs": "1278421b46f690974e087af11fc989eecef21ad605f9707d8da81180391b0478",
    },
}
APPROVED_COMPLEX_SCRIPT_DEPENDENCY_SCAN: dict[str, frozenset[str]] = {
    "appolon1908-hue/Keycloak": frozenset(
        {"scripts/review-plan.sh", "scripts/validate.sh"}
    ),
    "ingtrader21-spec/Middleware-": frozenset({"scripts/run_ci.sh"}),
    "appolon1908-hue/codestra": frozenset(
        {
            "scripts/ci/test-runtime-discovery-fixture.sh",
            "scripts/ci/test-runtime-discovery-host-proxy.sh",
        }
    ),
}
APPROVED_CONTROL_PLANE_WORKFLOW_SHA256: dict[str, dict[str, str]] = {
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/portfolio-production-ruleset-apply.yml": (
            "faae12baf6e9be3b6321feca2c594fe9"
            "418eb7bf06f22190619fcd10e127829c"
        ),
        ".github/workflows/portfolio-main-release-authorities.yml": (
            "393b612783e6daaf9105932e1f6e0b389"
            "9e21c8a67466533112117d6cf671ad4"
        ),
        ".github/workflows/exact-main-production-release.yml": (
            "5406ce4080316fb2e6e270b30a36e9b3e"
            "1324e2997502c019b3a37df06f72c5c"
        ),
        ".github/workflows/lead-automation-n8n-source-v1.yml": (
            "6b0cb7126987c14757bd1f48667bf81d"
            "50caaed769389cb30fc725766ea6bed6"
        ),
        ".github/workflows/middleware-ci.yml": (
            "31a2aac314d40f8f1b21418801d1a4005"
            "c91187e3ec316040570cdd556b97aed"
        ),
        ".github/workflows/integration-main-release-authorities.yml": (
            "910acf0149a0b9060544817a71577222a"
            "3ff117c75ad334886170d903d594150"
        ),
        ".github/workflows/production-reviewer-access.yml": (
            "fe8a41c98753e0a981a2673df0a7a324"
            "394b93a7ac5290dd684e0ede090d58de"
        ),
        ".github/workflows/python-quality-baseline.yml": (
            "35ecd2dac4328dea5615d5939d39e5682"
            "5794cedf919d80abb92a4272ccf81ca"
        ),
        ".github/workflows/required-ci.yml": "666a4524d0c3bf2c62de9d0b7b71a0106446f71709ab10c019a8b83bbef52de3",
        ".github/workflows/production-route-contract.yml": (
            "a12d81e9c8d3d1e14a68f4c9ef7f55e8"
            "487e09a83578e35bc3f2457bdb76bdb2"
        ),
        ".github/workflows/release-component-ci.yml": (
            "5a5f5b7e8aa57ba8faff72ffe4f6db"
            "a66846adcb107dac2cdb45a2f960e847bb"
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/ci.yml": "fffbdd8b7aad8b2679bcc608f0b487bf976c033a07786a0af5262d893867211a",
    },
    "appolon1908-hue/beyvra-frontend": {
        ".github/workflows/ci.yml": "7459a31c6b005e9345661b10ee8df45a570ac652280a2eacbcdfd4673fb115da",
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/ci.yml": "31d81c5be094a1510bc821ef4359bba591630d2273662f5de0683205d908c60d",
        ".github/workflows/dashboard-ci.yml": (
            "1f4c4add5bae50bc11fc2c7693c9a7ed"
            "e79f89300da81b9f7a6904d30462dac7"
        ),
        ".github/workflows/release-readiness.yml": (
            "22fb9e9447770c5b463b028d9ef6195d"
            "f53fbc99b2e8a467ba11e7a2b58b167b"
        ),
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/quality.yml": "9e8367e853316594a325fbcb0f22f1e701c35c205b15e66a5228ae8b4ce10ce4",
    },
    "appolon1908-hue/Moneybee-Backend": {
        ".github/workflows/ci.yml": (
            "0bed241476483a0ac38e0fc8bb2b06a2"
            "3b076645a6b0b355cf0420fcf4d2f451"
        ),
        ".github/workflows/release-backend-images.yml": (
            "1f14d41e27212554bb750403597ce726"
            "642527f61babf4e072d2cf2c03ab1345"
        ),
        ".github/workflows/secure-ci.yml": (
            "6ab4ebf30e47aee65ba3e1d7106ddd0c"
            "6feea546a57ebd289cf4fcfed9106e00"
        ),
    },
}
APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256: dict[str, dict[str, str]] = {
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/connector-runtime-api-ci.yml": "917ab06febf30f0d81146fc147794dace9510f7bb0a6fb903dd69b2244d4e1d0",
        ".github/workflows/connector-storage-ci.yml": "eada698e8756b76431a43f8d54d1aa192b9d964bca9a5e76d90476f35135bc7a",
        ".github/workflows/lead-automation-v1.yml": "9cdf5b9ce21f528bb8d0cb29b170586d212f5dfeb0e4ad237bb531a41bd89274",
        ".github/workflows/integrated-monitoring.yml": "2623d967318af06e56220d97c1c6d49855f1ae704435eced0d4319a89d32595a",
        ".github/workflows/odoo-calling-contract.yml": (
            "03d93c41717cf69ac764a9665eb42fb71"
            "7d342aef6ff1fc52f8d050f7feb580d"
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/email-boundary-ci.yml": "13ec97e8fb3cf77dcea400c2c8d4d5f089a567852ebcfa7f8efc581efa6f1fd6",
        ".github/workflows/enterprise-api.yml": "0d41ab216db01c92761c261f303ddc949b7eba43d4c7d323144028089e9ac99d",
        ".github/workflows/registration-safety-ci.yml": "8359be31987dbfc7b3d570ce12201fd0e94a21c71c8dec303052ef44a87fb25c",
        ".github/workflows/security-command-ci.yml": "a47a0f78eb38348b2c23e784e9048b1311297ffe30080c4b063048b296e66d41",
        ".github/workflows/workspace-api.yml": "abf3d41bfe718ecd343cd540ea27cd330c16294b192a7aa37f0435b895cc90b5",
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/ci.yml": "31d81c5be094a1510bc821ef4359bba591630d2273662f5de0683205d908c60d",
        ".github/workflows/release-readiness.yml": "22fb9e9447770c5b463b028d9ef6195df53fbc99b2e8a467ba11e7a2b58b167b",
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/backend-production.yml": (
            "45b2918627995cb3491f55b3a3b537e"
            "4a34598d7b32877879b9e2c912c266591"
        ),
    },
}
APPROVED_OFFLINE_RUN_SHA256: dict[str, dict[str, frozenset[str]]] = {
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/trusted-production-orchestrator-gate.yml": frozenset(
            {"6ceced166ce773d56bb54f544dee4508a60803465987e93cb8d719ee96df6df3"}
        ),
        ".github/workflows/production-orchestrator-contract.yml": frozenset(
            {"42481d485e47eb31f2e133ba690417a5a5927fccfb40ecd18836e5ad1ee3b1a9"}
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/certification-ci.yml": frozenset(
            {"90342c1a6aff24d02b18a064f6fc1affcddbe05fb894ccb22122b9a649358387"}
        ),
    },
}
APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256 = {
    "ingtrader21-spec/Middleware-": (
        "4bc320b1ae18cb4e0d97a1a3d5710638"
        "37476f3bcafde2086100687d89ea7954"
    ),
}
APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256: dict[
    str, dict[str, dict[str, str]]
] = {
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/portfolio-production-ruleset-apply.yml": {
            "config/ai-production-branch-ruleset.v1.json": "52db5e583b88edb069ba1d7b829d1f49ad820d0bb90e41bcf5b94e4074403ae1",
            "config/portfolio-repositories.v1.json": "bcd65e22c20ee01812d0269af659fc09f81e0fdec78500437eebac937ae72fdf",
            "scripts/apply_portfolio_production_ruleset.py": "31663d6f3101e593310b25a38035620d47a317d6a088193f6b550b730d0d39b0",
            "scripts/portfolio_ruleset/__init__.py": "054ac3779dc21008042eada02c91f85c57612afc37163592f1aa90b9ee4b6b18",
            "scripts/portfolio_ruleset/common.py": "1a8839c4dddbca4c3477a3a7cfd9d41a5f8d0c1f8361a07e85db2057f5dfdf70",
            "scripts/portfolio_ruleset/github_api.py": (
                "e0625083ed35b7a1fd46f67b3f91b7d"
                "166887f7d054d989dd2cac1d3d04dae6d"
            ),
            "scripts/portfolio_ruleset/rollout.py": "91ccf5b6b8f4b119dbb3dc451c42200ab00026b91751ce9f014bd4a0c4275022",
            "tests/test_portfolio_production_ruleset.py": "9f9605907a9c6a0e4a2b3446be236dbe7a5b49efeec0ce8b4d72ea30eda31e8d",
        },
        ".github/workflows/portfolio-main-release-authorities.yml": {
            "config/portfolio-main-release-authorities.v1.json": (
                "98da5d7935cc0f0e9e6c1fcfc820956b"
                "618e05a5109c6ee7f16c698cff719897"
            ),
            "scripts/apply_portfolio_main_release_authorities.py": (
                "1294f61d095d93328f403dfd9d2f1484f5debb3e945dca674d47bbd09f3ed0f0"
            ),
            "scripts/apply_portfolio_release_reviewer_access.py": (
                "f34213e61c3eba4ac1a9191883421ad3e408c35cba4c91f9fda09e09ffe75d10"
            ),
            "tests/test_portfolio_main_release_authorities.py": (
                "5d3a931ddad6f2cb68a85deee345d10a045762e6c1433f93383c4644e071d664"
            ),
            "tests/test_portfolio_release_reviewer_access.py": (
                "1f5fe17545344ae89daed538be0b44a07"
                "5f0f522d2a9990e5139deb3e526575b"
            ),
        },
        ".github/workflows/integration-main-release-authorities.yml": {
            "config/integration-main-release-authorities.v1.json": (
                "93ee2e898759a2c6cf79cf9afc3c3d58"
                "d9eaf84515f4207043e9da8c99e88ba1"
            ),
            "scripts/apply_integration_main_release_authorities.py": (
                "95b9c27abd309b1efe579672fdb8b89fe"
                "aed55e8e9334c50913b2e422ad771a7"
            ),
            "scripts/apply_integration_main_release_authorities_base.py": (
                "a55e6092984b0465c6159a4a77759d3b"
            "ae01817e0bf6d37356937b60ec06d019"
            ),
            "scripts/apply_integration_main_release_authorities_v2.py": (
                "0ef82f4d9bab61826bdf7c4c22a37d62"
            "8899ab19996f95d9555e4ef72f11e1e7"
            ),
        },
        ".github/workflows/production-reviewer-access.yml": {
            "config/production-reviewer-access.v1.json": (
                "b914202e589174360b9c9d2c4f2d35ce"
            "3d01f1188b68021b1402eb184ae7abd5"
            ),
            "scripts/apply_production_reviewer_access.py": (
                "ca679a9caa29ef2d80d1e4cb87d3748805bc742a78729aacf95436af75529faa"
            ),
            "scripts/apply_production_reviewer_access_base.py": (
                "a36d9cfe647f0ddd6ac396255d00ce6e"
            "4a1676d133c5cf2d236060cac339d6e5"
            ),
        },
    },
}
APPROVED_UNRESOLVED_SCRIPT_TARGETS: dict[str, frozenset[str]] = {
    # Nuxt emits this checked-build output before the CI smoke-test step.
    # Repository-owned and working-directory-relative scripts are resolved and
    # inspected below; no deployment script belongs in this exception list.
    "appolon1908-hue/Telnexa-web": frozenset({".output/server/index.mjs"}),
}
APPROVED_READ_ONLY_SCRIPT_INVOCATIONS: dict[
    str, dict[str, tuple[str, frozenset[tuple[str, ...]]]]
] = {
    "appolon1908-hue/Keycloak": {
        "scripts/validate-repository-name-authority.py": (
            "d56d85a41734dc468efecb99d590d0d33267dcd1c84f4ff4dd3fa93c2076bd96",
            frozenset({(), ("--live",)}),
        ),
    },
    "ingtrader21-spec/Middleware-": {
        "scripts/run_ci.sh": (
            "64d7c92279dd442144c7e1f74c3e48f0ab5d5db105238a534dcf8ccd99e93138",
            frozenset({()}),
        ),
        "scripts/validate_middleware_authority_convergence.py": (
            "fd1f54c2f85567aa1cf776b159cc16608041950152c41341eeada6bd2e666be8",
            frozenset({()}),
        ),
        "scripts/apply_portfolio_main_release_authorities.py": (
            "1294f61d095d93328f403dfd9d2f1484f5debb3e945dca674d47bbd09f3ed0f0",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_portfolio_release_reviewer_access.py": (
            "f34213e61c3eba4ac1a9191883421ad3e408c35cba4c91f9fda09e09ffe75d10",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/audit_release_endpoints.py": (
            "922655600ccaa1a0ba72fefd721bd6e370e4f0da430b7b4b0d858ed2826f067a",
            frozenset({()}),
        ),
        "scripts/apply_integration_main_release_authorities.py": (
            "95b9c27abd309b1efe579672fdb8b89feaed55e8e9334c50913b2e422ad771a7",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_integration_main_release_authorities_v2.py": (
            "0ef82f4d9bab61826bdf7c4c22a37d628899ab19996f95d9555e4ef72f11e1e7",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_production_reviewer_access.py": (
            "ca679a9caa29ef2d80d1e4cb87d3748805bc742a78729aacf95436af75529faa",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_repository_governance.py": (
            "dc875b6bf0223fb2d99ff70dfb99b075724ec6bf2b5aa3ef0e389b983c45fafc",
            frozenset({(), ("--apply",), ("--verify-live",)}),
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        "operations/one_click_readonly_release.py": (
            "66f853c64b440615179cddb3a67ad027017fec0d17d5ed56178ec5b2ce9173ba",
            frozenset({("--self-test",)}),
        ),
    },
    "appolon1908-hue/beyvra-frontend": {
        "operations/verify_backend_certification.sh": (
            "ff6afa3966de2e67d7cceec60cc7e018b2cb7f8da261858e1d80b2a2a411e8f0",
            frozenset({()}),
        ),
    },
}
REQUIRED_NATIVE_WORKFLOWS: dict[str, dict[str, str]] = {
    "appolon1908-hue/Infustruction-repo": {
        "runtime_certification": ".github/workflows/staging-readonly-certification.yml",
    },
    "appolon1908-hue/Keycloak": {
        "plan_apply": ".github/workflows/deploy.yml",
        "drift_review": ".github/workflows/drift-review.yml",
    },
    "ingtrader21-spec/Middleware-": {
        "signed_release": ".github/workflows/release.yml",
        "runtime_certification": ".github/workflows/production-runtime-certification.yml",
    },
    "appolon1908-hue/codestra": {
        "build_deploy": ".github/workflows/deploy.yml",
    },
}
ALLOWED_RELEASE_VALIDATOR_COMMAND_PREFIXES = {
    ("cosign", "verify"),
    ("cosign", "verify-attestation"),
    ("docker", "buildx", "imagetools", "inspect"),
    ("docker", "login"),
    ("gh", "attestation", "verify"),
    ("git", "ls-tree", "-r", "-z"),
    ("git", "rev-parse"),
    ("git", "status"),
}
ALLOWED_RELEASE_VALIDATOR_IMPORTS = {
    "__future__",
    "base64",
    "copy",
    "email",
    "hashlib",
    "io",
    "json",
    "os",
    "pathlib",
    "re",
    "subprocess",
    "sys",
    "tempfile",
    "typing",
    "urllib",
    "yaml",
    "zipfile",
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def release_validator_security_fingerprint(source: str) -> str:
    """Bind release policy bytes without introducing a digest cycle.

    The normalized assignments contain contract-validator hashes or source-tree
    hashes that themselves include this validator. Their names, uniqueness, and
    presence remain bound; only their assigned values are normalized. Every
    other byte of the release validator is covered by this fingerprint.
    """

    try:
        tree = ast.parse(source, filename=str(RELEASE_VALIDATOR_PATH))
    except SyntaxError as error:
        raise ContractError("release-intent validator is not valid Python") from error
    source_bytes = source.encode("utf-8")
    line_starts = [0]
    for line in source_bytes.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))

    replacements: list[tuple[int, int, bytes]] = []
    seen: set[str] = set()
    for node in tree.body:
        names: list[str] = []
        binding_value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            binding_value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
            binding_value = node.value
        matched = set(names) & RELEASE_VALIDATOR_NON_SELF_REFERENTIAL_BINDINGS
        if not matched:
            continue
        require(
            len(names) == 1 and len(matched) == 1,
            "release-validator trust binding assignment is ambiguous",
        )
        name = names[0]
        require(name not in seen, "release-validator trust binding is assigned more than once")
        if binding_value is None:
            raise ContractError("release-validator trust binding has no value")
        if name == "EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256":
            if not isinstance(binding_value, ast.Dict):
                raise ContractError("release-validator source closure binding is invalid")
            literal_bindings: dict[str, str] = {}
            for key_node, value_node in zip(binding_value.keys, binding_value.values):
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    bound_repository = key_node.value
                elif isinstance(key_node, ast.Name) and key_node.id == "CONTROLLER_REPOSITORY":
                    bound_repository = "appolon1908-hue/codestra-production-platform"
                else:
                    raise ContractError("release-validator source closure key is not static")
                try:
                    bound_digest = ast.literal_eval(value_node)
                except (TypeError, ValueError) as error:
                    raise ContractError(
                        "release-validator source closure digest is not static"
                    ) from error
                require(
                    isinstance(bound_digest, str)
                    and re.fullmatch(r"[0-9a-f]{64}", bound_digest) is not None,
                    "release-validator source closure binding is invalid",
                )
                require(
                    bound_repository not in literal_bindings,
                    "release-validator source closure binding contains duplicates",
                )
                literal_bindings[bound_repository] = bound_digest
            require(
                set(literal_bindings)
                == set(EXPECTED_RELEASE_VALIDATOR_SECURITY_SHA256)
                | {"appolon1908-hue/codestra-production-platform"},
                "release-validator source closure catalog is incomplete",
            )
        else:
            try:
                literal_value = ast.literal_eval(binding_value)
            except (TypeError, ValueError) as error:
                raise ContractError(
                    "release-validator trust binding is not a static literal"
                ) from error
            require(
                isinstance(literal_value, str)
                and re.fullmatch(r"[0-9a-f]{64}", literal_value) is not None,
                "release-validator contract hash binding is invalid",
            )
        end_lineno = binding_value.end_lineno
        end_col_offset = binding_value.end_col_offset
        if not isinstance(end_lineno, int) or not isinstance(end_col_offset, int):
            raise ContractError("release-validator trust binding location is unavailable")
        require(
            1 <= binding_value.lineno <= len(line_starts)
            and 1 <= end_lineno <= len(line_starts),
            "release-validator trust binding location is invalid",
        )
        replacements.append(
            (
                line_starts[binding_value.lineno - 1] + binding_value.col_offset,
                line_starts[end_lineno - 1] + end_col_offset,
                b'"<normalized-independent-trust-binding>"',
            )
        )
        seen.add(name)
    require(
        seen == RELEASE_VALIDATOR_NON_SELF_REFERENTIAL_BINDINGS,
        "release-validator non-self-referential trust bindings are incomplete",
    )
    for start, end, replacement in sorted(replacements, reverse=True):
        require(
            0 <= start < end <= len(source_bytes),
            "release-validator trust binding byte range is invalid",
        )
        source_bytes = source_bytes[:start] + replacement + source_bytes[end:]
    return hashlib.sha256(source_bytes).hexdigest()


def validate_release_validator_trust_root(source: str, repository: object) -> None:
    if not isinstance(repository, str):
        raise ContractError("release-validator repository identity is invalid")
    expected = EXPECTED_RELEASE_VALIDATOR_SECURITY_SHA256.get(repository)
    require(
        isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
        "release-validator independent trust root is missing",
    )
    require(
        release_validator_security_fingerprint(source) == expected,
        "release-validator independent trust root mismatch",
    )


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_mapping(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(message)
    return value


def require_string_list(value: object, message: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ContractError(message)
    if nonempty and not value:
        raise ContractError(message)
    if not all(isinstance(item, str) and item for item in value):
        raise ContractError(message)
    return [item for item in value if isinstance(item, str)]


def load_contract() -> dict[str, Any]:
    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "contract is missing or unsafe")
    value = json.loads(
        CONTRACT_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    require(isinstance(value, dict), "contract must be a JSON object")
    return value


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mappings."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(key not in result, "workflow contains a duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


@dataclass(frozen=True)
class WorkflowJob:
    data: dict[str, Any]
    raw: str
    working_directory: str | None
    shell: str | None
    environment: dict[str, Any]


def default_working_directory(value: dict[str, Any], path: str) -> str | None:
    defaults = value.get("defaults")
    if defaults is None:
        return None
    require(isinstance(defaults, dict), f"workflow defaults are invalid: {path}")
    run = defaults.get("run")
    if run is None:
        return None
    require(isinstance(run, dict), f"workflow run defaults are invalid: {path}")
    working_directory = run.get("working-directory")
    require(
        working_directory is None
        or isinstance(working_directory, str)
        and bool(working_directory),
        f"workflow working-directory is invalid: {path}",
    )
    return working_directory


def default_shell(value: dict[str, Any], path: str) -> str | None:
    defaults = value.get("defaults")
    if defaults is None:
        return None
    require(isinstance(defaults, dict), f"workflow defaults are invalid: {path}")
    run = defaults.get("run")
    if run is None:
        return None
    require(isinstance(run, dict), f"workflow run defaults are invalid: {path}")
    shell = run.get("shell")
    require(
        shell is None or isinstance(shell, str) and bool(shell),
        f"workflow shell is invalid: {path}",
    )
    return shell


def workflow_jobs(workflow: str, path: str) -> dict[str, WorkflowJob]:
    """Parse GitHub Actions jobs with YAML semantics and source spans."""

    try:
        document = yaml.load(workflow, Loader=UniqueKeyLoader)
        root = yaml.compose(workflow, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"workflow is not valid YAML: {path}") from exc
    require(isinstance(document, dict), f"workflow is not a mapping: {path}")
    workflow_working_directory = default_working_directory(document, path)
    workflow_shell = default_shell(document, path)
    workflow_environment = document.get("env", {})
    require(
        isinstance(workflow_environment, dict)
        and all(isinstance(name, str) and bool(name) for name in workflow_environment),
        f"workflow environment is invalid: {path}",
    )
    jobs_value = document.get("jobs")
    require(isinstance(jobs_value, dict) and bool(jobs_value), f"workflow has no jobs: {path}")
    require(isinstance(root, yaml.nodes.MappingNode), f"workflow root is invalid: {path}")
    jobs_node: yaml.nodes.MappingNode | None = None
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.nodes.ScalarNode) and key_node.value == "jobs":
            require(isinstance(value_node, yaml.nodes.MappingNode), f"workflow jobs are invalid: {path}")
            jobs_node = value_node
            break
    if jobs_node is None:
        raise ContractError(f"workflow jobs source is missing: {path}")
    lines = workflow.splitlines()
    result: dict[str, WorkflowJob] = {}
    for key_node, value_node in jobs_node.value:
        require(isinstance(key_node, yaml.nodes.ScalarNode), f"workflow job name is invalid: {path}")
        name = key_node.value
        data = jobs_value.get(name)
        require(isinstance(data, dict), f"workflow job is not a mapping: {path}:{name}")
        job_environment = data.get("env", {})
        require(
            isinstance(job_environment, dict)
            and all(isinstance(key, str) and bool(key) for key in job_environment),
            f"workflow job environment is invalid: {path}:{name}",
        )
        raw = "\n".join(lines[key_node.start_mark.line : value_node.end_mark.line]) + "\n"
        job_working_directory = default_working_directory(data, path)
        job_shell = default_shell(data, path)
        result[name] = WorkflowJob(
            data=data,
            raw=raw,
            working_directory=job_working_directory or workflow_working_directory,
            shell=job_shell or workflow_shell,
            environment={**workflow_environment, **job_environment},
        )
    require(set(result) == set(jobs_value), f"workflow job source mismatch: {path}")
    return result


def workflow_steps(job: WorkflowJob, path: str) -> list[dict[str, Any]]:
    value = job.data.get("steps")
    if value is None:
        return []
    require(isinstance(value, list), f"job steps are invalid: {path}")
    steps: list[dict[str, Any]] = []
    for item in value:
        require(isinstance(item, dict), f"workflow step is not a mapping: {path}")
        for key in ("env", "with"):
            require(
                key not in item or isinstance(item[key], dict),
                f"workflow step {key} is invalid: {path}",
            )
        steps.append(item)
    return steps


def step_working_directory(
    job: WorkflowJob,
    step: dict[str, Any],
    path: str,
) -> Path:
    value = step.get("working-directory", job.working_directory)
    if value is None:
        return ROOT
    require(
        isinstance(value, str)
        and bool(value)
        and "${{" not in value
        and "$" not in value,
        f"workflow working-directory is dynamic or invalid: {path}",
    )
    candidate = ROOT / value
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"workflow working-directory is missing or unsafe: {path}"
        ) from exc
    require(
        resolved.is_dir() and not resolved.is_symlink(),
        f"workflow working-directory is unsafe: {path}",
    )
    return resolved


def shell_tokens(script: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            script.replace("\\\n", " "),
            posix=True,
            punctuation_chars="|&;()\n",
        )
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        # Bash command substitutions and heredocs are richer than POSIX shlex.
        # A conservative token fallback keeps known runtime tools visible rather
        # than treating an unsupported shell construct as safe, and it must keep
        # every command boundary: a quoting failure in one command may not
        # merge a later publish/sign command into the first one.
        fallback: list[str] = []
        for line in script.replace("\\\n", " ").split("\n"):
            for segment in re.split(r"(\|\||&&|[;|&])", line):
                if segment in {"||", "&&", ";", "|", "&"}:
                    fallback.append(segment)
                else:
                    fallback.extend(re.findall(r"[A-Za-z0-9_./@${}:+-]+", segment))
            fallback.append("\n")
        return fallback


def shell_separator_token(token: str) -> bool:
    # shlex can coalesce adjacent punctuation such as a close parenthesis and
    # semicolon. Every token made only of separators ends the current command.
    return token in SHELL_SEPARATORS or (
        bool(token)
        and all(character in "\n&();|{}" for character in token)
        and any(character in "\n&();|" for character in token)
    )


def executable_name(token: str) -> str:
    return token.strip("$(){}[]").rsplit("/", 1)[-1]


def command_token_has_dynamic_executable(token: str) -> bool:
    """Reject expansion in the executable leaf, while allowing fixed path leaves."""

    return "$" in token.rsplit("/", 1)[-1]


def absolute_executable_is_unproved(token: str) -> bool:
    return Path(token).is_absolute() and not token.startswith(("/bin/", "/usr/bin/"))


def shell_command_bindings(
    tokens: list[str],
    before_index: int | None = None,
) -> dict[str, str]:
    """Return assignments that are effective before a command token.

    Only assignment words in command position establish bindings. Arguments
    such as ``echo tool=echo`` are not assignments, and later assignments must
    not retroactively change an earlier variable executable.
    """

    bindings: dict[str, str] = {}
    expect_command = True
    control = {"coproc", "do", "elif", "else", "if", "then", "until", "while"}
    for index, token in enumerate(tokens):
        if before_index is not None and index >= before_index:
            break
        if shell_separator_token(token):
            expect_command = True
            continue
        if token in control:
            expect_command = True
            continue
        if not expect_command:
            continue
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.+)", token, re.DOTALL)
        if match is not None:
            bindings[match.group(1)] = match.group(2)
            continue
        expect_command = False
    return bindings


def resolved_command_token(token: str, bindings: dict[str, str]) -> str:
    match = re.fullmatch(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))", token)
    if match is None:
        return token
    return bindings.get(match.group(1) or match.group(2), token)


def shell_command_substitutions(script: str) -> tuple[list[str], str] | None:
    """Return ``$()`` bodies and shell with those bodies safely elided."""

    def substitution_end(start: int) -> int | None:
        depth = 1
        quote: str | None = None
        escaped = False
        comment = False
        at_word_start = True
        index = start
        while index < len(script):
            character = script[index]
            if comment:
                if character == "\n":
                    comment = False
                    at_word_start = True
                index += 1
                continue
            if escaped:
                escaped = False
                at_word_start = False
                index += 1
                continue
            if character == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote == "'":
                if character == "'":
                    quote = None
                index += 1
                continue
            if character == "'" and quote is None:
                quote = "'"
                at_word_start = False
            elif character == '"':
                quote = None if quote == '"' else '"'
                at_word_start = False
            elif character == "#" and quote is None and at_word_start:
                comment = True
            elif character == "`":
                return None
            elif character == "$" and index + 1 < len(script) and script[index + 1] == "(":
                if index + 2 >= len(script) or script[index + 2] != "(":
                    depth += 1
                    index += 1
                at_word_start = False
            elif quote is None and character == "(":
                depth += 1
                at_word_start = True
            elif quote is None and character == ")":
                depth -= 1
                if depth == 0:
                    return index
                at_word_start = False
            elif quote is None and (character.isspace() or character in ";|&{}"):
                at_word_start = True
            else:
                at_word_start = False
            index += 1
        return None

    payloads: list[str] = []
    sanitized: list[str] = []
    previous_end = 0
    quote: str | None = None
    escaped = False
    comment = False
    at_word_start = True
    index = 0
    while index < len(script):
        character = script[index]
        if comment:
            if character == "\n":
                comment = False
                at_word_start = True
            index += 1
            continue
        if escaped:
            escaped = False
            at_word_start = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if character == "'" and quote is None:
            quote = "'"
            at_word_start = False
        elif character == '"':
            quote = None if quote == '"' else '"'
            at_word_start = False
        elif character == "#" and quote is None and at_word_start:
            comment = True
        elif character == "`":
            return None
        elif character == "$" and index + 1 < len(script) and script[index + 1] == "(":
            if index + 2 < len(script) and script[index + 2] == "(":
                at_word_start = False
            else:
                end = substitution_end(index + 2)
                if end is None:
                    return None
                payloads.append(script[index + 2 : end])
                sanitized.extend((script[previous_end:index], "SUBSTITUTION"))
                previous_end = end + 1
                index = end
                at_word_start = False
        elif quote is None and (character.isspace() or character in ";|&(){}"):
            at_word_start = True
        else:
            at_word_start = False
        index += 1
    sanitized.append(script[previous_end:])
    return payloads, "".join(sanitized)


def command_indexes(tokens: list[str]) -> list[int]:
    indexes: list[int] = []
    expect_command = True
    control = {"coproc", "do", "elif", "else", "if", "then", "until", "while"}
    skip_through = -1
    for index, token in enumerate(tokens):
        if index <= skip_through:
            continue
        if token == "[[" and expect_command:
            try:
                skip_through = tokens.index("]]", index + 1)
            except ValueError:
                indexes.append(index)
                expect_command = False
            continue
        if shell_separator_token(token):
            expect_command = True
            continue
        if token in control:
            expect_command = True
            continue
        if not expect_command:
            continue
        if token in {"[", "[["}:
            terminator = "]" if token == "[" else "]]"
            try:
                skip_through = tokens.index(terminator, index + 1)
            except ValueError:
                indexes.append(index)
                expect_command = False
                continue
            expect_command = False
            continue
        if executable_name(token) in SHELL_WRAPPERS:
            resolved = wrapped_executable_index(tokens, index)
            if resolved is None:
                expect_command = False
                continue
            indexes.append(resolved)
            skip_through = resolved
            expect_command = False
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            continue
        indexes.append(index)
        expect_command = False
    return indexes


def wrapped_executable_index(tokens: list[str], start: int) -> int | None:
    """Resolve common shell wrappers without treating their options as commands."""

    no_value_options = {
        "!": set(),
        "command": {"--"},
        "env": {"--", "--ignore-environment", "--null", "-0", "-i"},
        "exec": {"--", "-c", "-l"},
        "nohup": set(),
        "sudo": {
            "--",
            "--preserve-env",
            "-E",
            "-H",
            "-K",
            "-S",
            "-b",
            "-k",
            "-n",
        },
        "systemd-run": {"--", "--wait"},
        "time": {"--", "-a", "-p", "-v"},
    }
    value_options = {
        "env": {"--chdir", "--split-string", "--unset", "-c", "-s", "-u"},
        "exec": {"-a"},
        "sudo": {
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--prompt",
            "--user",
            "-c",
            "-g",
            "-p",
            "-r",
            "-t",
            "-u",
        },
        "time": {"--format", "--output", "-f", "-o"},
    }
    index = start
    while index < len(tokens):
        wrapper = executable_name(tokens[index])
        if wrapper not in no_value_options:
            return index
        index += 1
        if wrapper == "command" and index < len(tokens) and tokens[index] in {"-v", "-V"}:
            return None
        while index < len(tokens):
            token = tokens[index]
            lower = token.lower()
            option_key = lower if token.startswith("--") else token
            if shell_separator_token(token):
                return None
            if wrapper == "env" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                index += 1
                continue
            if option_key in no_value_options[wrapper]:
                index += 1
                continue
            if wrapper == "sudo" and lower.startswith("--preserve-env="):
                index += 1
                continue
            if option_key in value_options.get(wrapper, set()):
                index += 2
                continue
            if any(
                lower.startswith(f"{option}=")
                for option in value_options.get(wrapper, set())
                if option.startswith("--")
            ):
                index += 1
                continue
            if token.startswith("-"):
                # Unknown wrapper options are ambiguous, so classify the
                # wrapper itself as unsafe rather than skipping a payload.
                return start
            break
    return None


def raw_command_arguments(tokens: list[str], index: int) -> list[str]:
    arguments: list[str] = []
    for token in tokens[index + 1 :]:
        if shell_separator_token(token):
            break
        arguments.append(token)
    return arguments


def command_arguments(tokens: list[str], index: int) -> list[str]:
    return [executable_name(token) for token in raw_command_arguments(tokens, index)]


def command_consumes_pipeline(tokens: list[str], index: int) -> bool:
    return index > 0 and tokens[index - 1] == "|"


def runtime_cli_operation_is_dynamic(name: str, arguments: list[str]) -> bool:
    """Fail closed only when a runtime CLI's operation token is unresolved."""

    value_options = {
        "helm": {"--kube-apiserver", "--kube-context", "--kube-token", "--namespace", "-n"},
        "kubectl": {"--context", "--kubeconfig", "--namespace", "--server", "--token", "-n", "-s"},
        "terraform": {"-chdir"},
        "tofu": {"-chdir"},
    }.get(name, set())
    skip_value = False
    for token in arguments:
        if skip_value:
            skip_value = False
            continue
        lower = token.lower()
        option = lower.split("=", 1)[0]
        if option in value_options:
            skip_value = "=" not in token
            continue
        if token.startswith("-"):
            continue
        return "$" in token or "${{" in token
    return False


def xargs_payload(arguments: list[str]) -> str | None:
    """Return a statically delimited xargs command, or fail closed with None."""

    value_options = {
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--process-slot-var",
        "--replace",
        "-a",
        "-d",
        "-i",
        "-l",
        "-n",
        "-p",
        "-s",
    }
    no_value_options = {
        "--exit",
        "--no-run-if-empty",
        "--null",
        "--open-tty",
        "--show-limits",
        "--verbose",
        "-0",
        "-r",
        "-t",
        "-x",
    }
    index = 0
    while index < len(arguments):
        token = arguments[index]
        lower = token.lower()
        if token == "SUBSTITUTION" or "$" in token:
            # Expansions can move the option/command boundary or synthesize a
            # replacement option after static parsing.
            return None
        if (
            lower in {"--replace", "-i"}
            or lower.startswith("--replace=")
            or token.startswith("-I")
        ):
            # Replacement input can become the executable itself, so no
            # static payload remains to prove read-only.
            return None
        if lower in no_value_options:
            index += 1
            continue
        if lower in value_options:
            if index + 1 >= len(arguments):
                return None
            index += 2
            continue
        if any(
            lower.startswith(f"{option}=")
            for option in value_options
            if option.startswith("--")
        ):
            index += 1
            continue
        if token.startswith("-"):
            return None
        payload_tokens = arguments[index:]
        payload_name = executable_name(payload_tokens[0])
        if payload_name in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
            inline = interpreter_payload(payload_tokens, 0)
            if inline == "" or (
                inline is None
                and interpreter_script_target(payload_tokens, 0) is None
            ):
                # xargs appends stdin items after the fixed arguments. For
                # inline interpreters or an interpreter without a fixed script,
                # that input becomes executable code or a script path.
                return None
        return " ".join(payload_tokens)
    # With no explicit command, xargs invokes echo and cannot launch a hidden
    # repository/runtime executable.
    return ""


def interpreter_payload(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name == "eval":
        return tokens[index + 1] if index + 1 < len(tokens) else ""
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    payload_options = {
        "node": {"--eval", "-e"},
        "perl": {"-e"},
        "php": {"-r"},
        "python": {"-c"},
        "python3": {"-c"},
        "ruby": {"-e"},
    }.get(name, {"-c"})
    for option_index in range(index + 1, len(tokens)):
        if tokens[option_index] in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        token = tokens[option_index]
        if token in payload_options:
            return tokens[option_index + 1] if option_index + 1 < len(tokens) else ""
        for option in payload_options:
            if option.startswith("--") and token.startswith(f"{option}="):
                return token.split("=", 1)[1]
            if len(option) == 2 and token.startswith(option) and len(token) > 2:
                return token[len(option) :].removeprefix("=")
    return None


def interpreter_script_target(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    shellcheck_only = False
    skip_option_value = False
    for token in tokens[index + 1 :]:
        if token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        if skip_option_value:
            skip_option_value = False
            continue
        if (
            token == "-m"
            or token == "-"
            or token.startswith("<<")
            or token == "-c"
            or token == "-e" and name in {"node", "perl", "ruby"}
            or token == "--eval" and name == "node"
            or token == "-r" and name == "php"
        ):
            return None
        if token == "-n" and name in SHELL_INTERPRETERS:
            shellcheck_only = True
            continue
        if name == "node" and token in {"--check", "-c"}:
            shellcheck_only = True
            continue
        if token in {"-o", "--option"}:
            skip_option_value = True
            continue
        if token.startswith("-"):
            if name in SHELL_INTERPRETERS and "o" in token[1:]:
                skip_option_value = True
            continue
        if "=" in token and not token.startswith(("./", "../")):
            continue
        return None if shellcheck_only else token
    return None


def python_source_has_runtime_mutation(
    source: str,
    *,
    include_read_only_runtime_contact: bool = False,
) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    aliases: dict[str, str] = {}
    command_bindings: dict[str, list[ast.expr]] = {}
    function_returns: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    command_bindings.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                command_bindings.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_returns[node.name] = [
                child.value
                for child in ast.walk(node)
                if isinstance(child, ast.Return) and child.value is not None
            ]

    def binding_root(node: ast.expr) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    mutated_command_bindings: set[str] = set()
    command_mutators = {
        "__delitem__",
        "__iadd__",
        "__imul__",
        "__setitem__",
        "append",
        "clear",
        "extend",
        "insert",
        "pop",
        "remove",
        "reverse",
        "sort",
    }
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for target in targets:
            if isinstance(target, (ast.Attribute, ast.Subscript)):
                target_root = binding_root(target)
                if target_root is not None and target_root in command_bindings:
                    mutated_command_bindings.add(target_root)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            call_root = binding_root(node.func.value)
            if call_root is not None and call_root in command_bindings and node.func.attr in command_mutators:
                mutated_command_bindings.add(call_root)

    def qualified_name(node: ast.expr, seen: frozenset[str] = frozenset()) -> str:
        if isinstance(node, ast.Name):
            if node.id in command_bindings and node.id not in seen:
                resolved = {
                    qualified_name(value, seen | {node.id})
                    for value in command_bindings[node.id]
                }
                resolved.discard("")
                if not resolved:
                    return ""
                risky = sorted(
                    value
                    for value in resolved
                    if value == "getattr"
                    or value.startswith(("os.", "subprocess."))
                    or set(re.split(r"[^a-z0-9_]+", value.lower()))
                    & (NETWORK_CLIENT_HINTS | DATABASE_CLIENT_HINTS)
                )
                return risky[0] if risky else sorted(resolved)[0]
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = qualified_name(node.value, seen)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            constructor = qualified_name(node.func, seen)
            returned = function_returns.get(constructor, [])
            return_marker = f"__return__:{constructor}"
            if returned and return_marker not in seen:
                resolved = {
                    qualified_name(value, seen | {return_marker})
                    for value in returned
                }
                resolved.discard("")
                risky = sorted(
                    value
                    for value in resolved
                    if value.startswith(("os.", "subprocess."))
                    or set(re.split(r"[^a-z0-9_]+", value.lower()))
                    & (NETWORK_CLIENT_HINTS | DATABASE_CLIENT_HINTS)
                )
                if risky:
                    return risky[0]
            if constructor.rsplit(".", 1)[-1].lower() == "wrap_socket":
                # TLS wrappers retain the mutation capability of the wrapped
                # socket. Preserve that provenance through assignments such as
                # ``channel = context.wrap_socket(socket.socket())`` so later
                # ``channel.connect``/``channel.write`` calls fail closed.
                return f"socket.{constructor}"
            hints = set(re.split(r"[^a-z0-9_]+", constructor.lower()))
            if hints & (NETWORK_CLIENT_HINTS | DATABASE_CLIENT_HINTS):
                return constructor
            return ""
        if isinstance(node, ast.Subscript):
            if (
                isinstance(node.value, (ast.List, ast.Tuple))
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, int)
                and not isinstance(node.slice.value, bool)
            ):
                index = node.slice.value
                if -len(node.value.elts) <= index < len(node.value.elts):
                    return qualified_name(node.value.elts[index], seen)
            return ""
        if isinstance(node, ast.Lambda):
            return qualified_name(node.body, seen)
        if isinstance(node, ast.NamedExpr):
            return qualified_name(node.value, seen)
        return ""

    def restricted_callable_name(name: str) -> bool:
        method = name.rsplit(".", 1)[-1].lower()
        receiver = name.rsplit(".", 1)[0].lower()
        receiver_hints = set(re.split(r"[^a-z0-9_]+", receiver))
        return (
            name
            in {
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.getoutput",
                "subprocess.getstatusoutput",
                "subprocess.run",
            }
            or name.startswith("os.exec")
            or name.startswith("os.spawn")
            or name
            in {
                "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell",
                "os.popen",
                "os.posix_spawn",
                "os.posix_spawnp",
                "os.system",
                "urllib.request.urlopen",
                "urllib.request.urlretrieve",
            }
            or (
                method in NETWORK_MUTATION_METHODS
                and bool(receiver_hints & NETWORK_CLIENT_HINTS)
            )
            or (
                method in DATABASE_MUTATION_METHODS
                and bool(receiver_hints & DATABASE_CLIENT_HINTS)
            )
            or (
                method == "request"
                and bool(receiver_hints & NETWORK_CLIENT_HINTS)
            )
        )

    def expression_has_restricted_callable(value: ast.expr) -> bool:
        invoked = {
            id(child.func)
            for child in ast.walk(value)
            if isinstance(child, ast.Call)
        }
        attribute_receivers = {
            id(child.value)
            for child in ast.walk(value)
            if isinstance(child, ast.Attribute)
        }
        return any(
            id(child) not in invoked | attribute_receivers
            and isinstance(child, (ast.Name, ast.Attribute))
            and restricted_callable_name(qualified_name(child))
            for child in ast.walk(value)
        )

    runtime_modules = {
        "aiosmtplib",
        "ansible",
        "azure",
        "boto3",
        "botocore",
        "ctypes",
        "digitalocean",
        "docker",
        "fabric",
        "kubernetes",
        "paramiko",
        "posix",
        "pty",
        "runpy",
        "smtplib",
        "xmlrpc",
    }
    if any(
        value.split(".", 1)[0] in runtime_modules
        or value == "google.cloud"
        or value.startswith("google.cloud.")
        for value in aliases.values()
    ):
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if expression_has_restricted_callable(node.value):
                return True
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, (ast.Attribute, ast.Subscript)) and (
                expression_has_restricted_callable(node.value)
            ):
                return True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = [*node.args.defaults, *node.args.kw_defaults]
            if any(
                value is not None and expression_has_restricted_callable(value)
                for value in defaults
            ):
                return True
            if any(
                isinstance(child, ast.Return)
                and child.value is not None
                and expression_has_restricted_callable(child.value)
                for child in ast.walk(node)
            ):
                return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if any(
            expression_has_restricted_callable(value)
            for value in [
                *node.args,
                *(keyword.value for keyword in node.keywords),
            ]
        ):
            return True
        if isinstance(node.func, (ast.NamedExpr, ast.Subscript)):
            return True
        if isinstance(node.func, ast.Call):
            return True
        qualified = qualified_name(node.func)
        if qualified in {
            "__import__",
            "builtins.__import__",
            "builtins.compile",
            "builtins.eval",
            "builtins.exec",
            "builtins.getattr",
            "builtins.globals",
            "builtins.locals",
            "builtins.setattr",
            "compile",
            "eval",
            "exec",
            "getattr",
            "globals",
            "importlib.import_module",
            "locals",
            "setattr",
        }:
            # Dynamic imports, code execution, and attribute lookup can hide a
            # process or network primitive from the qualified-name analysis.
            return True
        method = qualified.rsplit(".", 1)[-1].lower()
        receiver = qualified.rsplit(".", 1)[0].lower()
        receiver_hints = set(re.split(r"[^a-z0-9_]+", receiver))
        network_receiver = bool(receiver_hints & NETWORK_CLIENT_HINTS)
        database_receiver = bool(receiver_hints & DATABASE_CLIENT_HINTS)
        if include_read_only_runtime_contact and (
            method
            in {
                "create_connection",
                "create_datagram_endpoint",
                "create_server",
                "create_subprocess_exec",
                "create_subprocess_shell",
                "open_connection",
                "open_unix_connection",
                "start_server",
                "start_unix_server",
            }
            or
            qualified
            in {
                "asyncio.open_connection",
                "asyncio.start_server",
                "asyncio.start_unix_server",
                "asyncio.open_unix_connection",
            }
            or qualified.startswith(
                (
                    "aiohttp.",
                    "asyncio.BaseEventLoop.create_connection",
                    "asyncio.BaseEventLoop.create_server",
                    "asyncio.loop.create_connection",
                    "asyncio.loop.create_server",
                    "ftplib.",
                    "grpc.",
                    "http.client.",
                    "smtplib.",
                    "socket.",
                    "ssl.",
                    "websockets.",
                )
            )
        ):
            return True
        if include_read_only_runtime_contact and (
            network_receiver
            or database_receiver
            or qualified
            in {
                "urllib.request.Request",
                "urllib.request.urlopen",
            }
        ):
            # A plan-only release intent cannot prove that a direct network or
            # database read is not runtime contact. Fail closed even when the
            # operation is read-only.
            return True
        if qualified.startswith("asyncio.") and method in {
            "open_connection",
            "open_unix_connection",
        }:
            # The returned StreamWriter can send bytes through an arbitrary
            # destructured alias. Treat opening the writable stream as the
            # fail-closed boundary instead of trying to prove every alias.
            return True
        if method in NETWORK_MUTATION_METHODS and network_receiver:
            return True
        if method in DATABASE_MUTATION_METHODS and database_receiver:
            return True
        if method == "request" and network_receiver:
            http_method: str | None = None
            if node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str):
                    http_method = value.lower()
            for keyword in node.keywords:
                if keyword.arg == "method" and isinstance(keyword.value, ast.Constant):
                    value = keyword.value.value
                    if isinstance(value, str):
                        http_method = value.lower()
            if http_method is None or http_method in HTTP_MUTATION_METHODS:
                return True
        if method == "execute" and database_receiver:
            if not node.args:
                return True
            statement = node.args[0]
            if not (
                isinstance(statement, ast.Constant)
                and isinstance(statement.value, str)
                and SQL_MUTATION.search(statement.value) is None
            ):
                return True
        if qualified == "urllib.request.Request":
            if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
                keyword.arg is None for keyword in node.keywords
            ):
                return True
            if len(node.args) >= 2:
                return True
            for keyword in node.keywords:
                if keyword.arg == "data":
                    return True
                if keyword.arg == "method":
                    if not (
                        isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                        and keyword.value.value.lower() in {"get", "head"}
                    ):
                        return True
        if qualified == "urllib.request.urlopen":
            if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
                keyword.arg is None for keyword in node.keywords
            ):
                return True
            if len(node.args) >= 2:
                return True
            for keyword in node.keywords:
                if keyword.arg == "data":
                    return True
        if (
            qualified in {"os.system", "os.popen"}
            or qualified.startswith(("os.system.", "os.popen."))
            or qualified.startswith("os.exec")
            or qualified.startswith("os.spawn")
            or qualified in {"os.posix_spawn", "os.posix_spawnp"}
            or qualified
            in {
                "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell",
            }
            or qualified.startswith("subprocess.")
        ):
            # os.exec* and os.spawn* have multiple incompatible argument
            # layouts. They replace or launch a process, so reject them
            # conservatively instead of risking a skipped executable argument.
            if qualified.startswith(("os.exec", "os.spawn")) or qualified in {
                "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell",
                "os.posix_spawn",
                "os.posix_spawnp",
            }:
                return True
            if not node.args:
                return True
            argument = node.args[0]
            if isinstance(argument, ast.Name) and argument.id in command_bindings:
                if argument.id in mutated_command_bindings:
                    return True
                bindings = command_bindings[argument.id]
                if len(bindings) != 1:
                    return True
                argument = bindings[0]
            command = ""
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                command = argument.value
            elif isinstance(argument, (ast.List, ast.Tuple)):
                if not argument.elts:
                    return True
                first = argument.elts[0]
                if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                    return True
                values = [
                    item.value
                    for item in argument.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                executable = executable_name(first.value)
                if executable in {"ansible-playbook", "scp", "ssh"}:
                    return True
                if executable in {"helm", "kubectl", "terraform", "tofu"} and len(values) != len(argument.elts):
                    return True
                command = " ".join(values)
            else:
                return True
            if (
                contains_runtime_command(command)
                if include_read_only_runtime_contact
                else contains_runtime_mutation(command)
            ):
                return True
    return False


def python_source_has_runtime_contact(source: str) -> bool:
    return python_source_has_runtime_mutation(
        source,
        include_read_only_runtime_contact=True,
    )


def javascript_source_has_runtime_mutation(source: str) -> bool:
    lower = source.lower()

    def call_arguments(open_index: int) -> str | None:
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_index, len(source)):
            character = source[index]
            if escaped:
                escaped = False
                continue
            if character == "\\" and quote is not None:
                escaped = True
                continue
            if quote is not None:
                if character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
                continue
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return source[open_index + 1 : index]
        return None

    def split_top_level(arguments: str) -> list[str] | None:
        parts: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        escaped = False
        for index, character in enumerate(arguments):
            if escaped:
                escaped = False
                continue
            if character == "\\" and quote is not None:
                escaped = True
                continue
            if quote is not None:
                if character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
                continue
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth < 0:
                    return None
            elif character == "," and depth == 0:
                parts.append(arguments[start:index].strip())
                start = index + 1
        if quote is not None or depth != 0:
            return None
        parts.append(arguments[start:].strip())
        return parts

    for match in re.finditer(r"\b(?:require|import)\b", lower):
        open_index = match.end()
        while True:
            while open_index < len(lower) and lower[open_index].isspace():
                open_index += 1
            if lower.startswith("//", open_index):
                newline = re.search(r"[\r\n\u2028\u2029]", lower[open_index + 2:])
                if newline is None:
                    return True
                open_index += 2 + newline.end()
                continue
            if not lower.startswith("/*", open_index):
                break
            comment_end = lower.find("*/", open_index + 2)
            if comment_end < 0:
                # Malformed loader syntax is not safe to classify as a
                # static, read-only module import.
                return True
            open_index = comment_end + 2
        if lower.startswith("?.", open_index):
            # Optional-call syntax is executable JavaScript and can conceal a
            # computed loader specifier just like a direct call.
            open_index += 2
        if open_index >= len(lower) or lower[open_index] != "(":
            # A loader value can escape through an alias. It is not a proven
            # static read-only import, even if its eventual call is renamed.
            if match.group() == "require":
                suffix = lower[match.end():]
                prefix = lower[:match.start()]
                if re.match(r"\s*\.(?:apply|bind|call)\s*\(", suffix):
                    return True
                if (
                    re.search(r"(?<![=!<>])=(?!=)\s*$", prefix)
                    or re.search(r"(?:=>|\breturn)\s*$", prefix)
                ) and re.match(
                    r"(?:[ \t]*(?:;|,|\)|\]|\}|\r?\n|//|/\*)|[ \t]*$)",
                    suffix,
                ):
                    return True
            continue
        arguments = call_arguments(open_index)
        literal = None if arguments is None else re.fullmatch(
            r"""\s*(['"])([^'"\r\n]+)\1\s*""",
            arguments,
        )
        if literal is None:
            # Computed module specifiers can conceal networking or process
            # modules behind an otherwise arbitrary binding.
            return True
        module = literal.group(2).lower()
        if "\\" in module:
            # JavaScript escape sequences are resolved before module lookup.
            # Reject them rather than comparing an encoded spelling to the
            # runtime-module denylist.
            return True
        if re.fullmatch(
            r"(?:axios|got|superagent|undici|node-fetch|cross-fetch|"
            r"(?:node:)?(?:child_process|dgram|http|https|http2|net|tls)|"
            r"socket\.io-client)(?:/.*)?",
            module,
        ):
            # This parsed path is comment-aware, unlike a source regex, so a
            # renamed binding cannot conceal a mutating transport or launcher.
            return True
        if module.removeprefix("node:") in {
            "cluster",
            "vm",
            "worker_threads",
        }:
            return True

    if any(
        marker in lower
        for marker in (
            "node:child_process",
            "require('child_process')",
            'require("child_process")',
            "from 'child_process'",
            'from "child_process"',
        )
    ):
        # Destructuring and ordinary assignments can rename every launcher;
        # without a JavaScript AST, child-process access is not provably safe.
        return True
    if "getbuiltinmodule" in lower:
        # Dynamic built-in access can recover child_process without an import.
        return True
    if "createrequire" in lower:
        # createRequire constructs a loader whose later calls can be renamed
        # and computed; without a JavaScript AST its target is unprovable.
        return True
    websocket_aliases = set(
        re.findall(
            r"\b(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*"
            r"new\s+(?:globalthis\s*\.\s*)?websocket\s*\(",
            lower,
        )
    )
    if any(
        re.search(
            rf"\b{re.escape(alias)}\s*(?:\.\s*send|\[\s*['\"]send['\"]\s*\])\s*\(",
            lower,
        )
        for alias in websocket_aliases
    ):
        return True
    if re.search(r"\b(?:globalthis|window|self)\s*\[", lower):
        # Computed global access can assemble fetch, WebSocket, or another
        # network primitive without leaving a literal identifier to inspect.
        return True
    for match in re.finditer(r"\bfetch\b", lower):
        open_index = match.end()
        while open_index < len(source) and source[open_index].isspace():
            open_index += 1
        if open_index >= len(source) or source[open_index] != "(":
            # Passing or assigning fetch hides the eventual method and call.
            return True
        arguments = call_arguments(open_index)
        if arguments is None:
            return True
        parts = split_top_level(arguments)
        if parts is None or not parts or len(parts) > 2:
            return True
        if any(part.lstrip().startswith("...") for part in parts):
            return True
        if len(parts) == 2:
            options = parts[1].strip()
            if not (options.startswith("{") and options.endswith("}")):
                # An identifier or computed expression can conceal POST data.
                return True
            lowered_options = options.lower()
            if "..." in lowered_options:
                # Object spread can conceal a body or mutating method.
                return True
            if re.search(r"\bbody\s*:", lowered_options):
                return True
            methods = list(re.finditer(r"(?:\bmethod|['\"]method['\"])\s*:", lowered_options))
            if len(methods) > 1:
                return True
            if methods and re.match(
                r"\s*['\"](?:get|head)['\"]\s*(?:,|})",
                lowered_options[methods[0].end() :],
            ) is None:
                return True
    # Module imports can rename or construct clients in arbitrary ways. Until
    # those bindings are parsed, networking imports cannot prove read-only use.
    if re.search(
        r"(?:\bfrom\s*|\b(?:require|import)\s*\(\s*|\bimport\s*)"
        r"['\"](?:axios|got|superagent|undici|node-fetch|cross-fetch|"
        r"(?:node:)?(?:dgram|http|https|http2|net|tls)|socket\.io-client)"
        r"(?:/[^'\"]*)?['\"]",
        lower,
    ):
        return True
    client_aliases = set(
        re.findall(
            r"\b(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*"
            r"(?:api|api_client|axios|client|connection|http|httpx|requests|session|socket)"
            r"(?:\s*\.\s*create\s*\()?",
            lower,
        )
    )
    for pattern in (
        r"\bimport\s+([a-z_$][a-z0-9_$]*)\s+from\s*['\"](?:axios|https?|node:https?)['\"]",
        r"\bimport\s+\*\s+as\s+([a-z_$][a-z0-9_$]*)\s+from\s*['\"](?:axios|https?|node:https?)['\"]",
        r"\b(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*require\s*\(\s*['\"](?:axios|https?|node:https?)['\"]\s*\)",
    ):
        client_aliases.update(re.findall(pattern, lower))
    if client_aliases and any(
        re.search(
            rf"\b{re.escape(alias)}\s*\.\s*"
            r"(?:delete|patch|post|put|request|send|sendall)\s*\(",
            lower,
        )
        for alias in client_aliases
    ):
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|https|httpx|requests|session|socket)"
        r"\s*\.\s*(?:delete|patch|post|put|send|sendall)\s*\(",
        lower,
    ):
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|https|httpx|requests|session|socket)"
        r"\s*\.\s*request\s*\(",
        lower,
    ):
        # A generic request call can carry a computed write method. Reject it
        # unless a dedicated parser can prove the request is read-only.
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|httpx|requests|session)"
        r"\s*\.\s*request\s*\(",
        lower,
    ):
        # A computed or indirect method cannot be proven read-only without a
        # JavaScript parser, so generic request clients fail closed.
        return True
    if re.search(
        r"\b(?:conn|connection|cursor|database|db|engine|session)"
        r"\s*\.\s*(?:add|commit|create|delete|execute|executemany|flush|insert|save|update|upsert)\s*\(",
        lower,
    ):
        return True
    return False


def javascript_source_has_runtime_contact(source: str) -> bool:
    if javascript_source_has_runtime_mutation(source):
        return True
    lower = source.lower()
    if any(
        marker in lower
        for marker in (
            "@kubernetes/client-node",
            "dockerode",
            "node:http",
            "node:https",
            "node:net",
            "node:tls",
            "node:dgram",
            "from 'http'",
            'from "http"',
            "from 'https'",
            'from "https"',
            "from 'net'",
            'from "net"',
            "from 'tls'",
            'from "tls"',
            "require('http')",
            'require("http")',
            "require('https')",
            'require("https")',
            "require('net')",
            'require("net")',
            "require('tls')",
            'require("tls")',
        )
    ):
        return True
    if re.search(r"\bimport\s*\(", lower):
        # Dynamic imports can return a destructured or renamed network
        # primitive whose eventual call has no statically attributable receiver.
        return True
    if re.search(r"\brequire\b", lower):
        # CommonJS imports can compute a module name, execute module-level
        # effects, freely rename the result, and place comments between the
        # callee and opening parenthesis. Without a JavaScript AST and dependency
        # closure, any unresolved use of the identifier is not contact-free.
        return True
    return bool(
        re.search(r"\bfetch\b", lower)
        or re.search(r"\bwebsocket\b", lower)
        or re.search(
            r"\b(?:api|api_client|axios|client|connection|http|httpx|requests|session|socket)"
            r"\s*\.\s*(?:get|head|request|send)\s*\(",
            lower,
        )
    )


def heredoc_programs(script: str) -> list[tuple[str, str]]:
    lines = script.splitlines()
    programs: list[tuple[str, str]] = []
    index = 0
    marker_pattern = re.compile(
        r"<<(?P<strip>-?)\s*(?P<quote>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)(?=\s|$)"
    )
    while index < len(lines):
        match = marker_pattern.search(lines[index])
        if match is None:
            index += 1
            continue
        prefix = lines[index][: match.start()]
        tokens = shell_tokens(prefix)
        commands = command_indexes(tokens)
        require(bool(commands), "heredoc interpreter command is ambiguous")
        interpreter = executable_name(tokens[commands[-1]])
        marker = match.group("marker")
        strip_tabs = match.group("strip") == "-"
        end = index + 1
        while end < len(lines):
            candidate = lines[end].lstrip("\t") if strip_tabs else lines[end]
            if candidate == marker:
                break
            end += 1
        require(end < len(lines), "heredoc terminator is missing")
        if interpreter in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
            programs.append(
                (interpreter, "\n".join(lines[index + 1 : end]) + "\n")
            )
        index = end + 1
    return programs


def shell_without_heredoc_bodies(script: str) -> str:
    """Keep heredoc launch commands while removing non-shell body text."""

    lines = script.splitlines(keepends=True)
    output: list[str] = []
    marker_pattern = re.compile(
        r"<<(?P<strip>-?)\s*(?P<quote>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)(?=\s|$)"
    )
    index = 0
    while index < len(lines):
        line = lines[index]
        line_without_newline = line.rstrip("\r\n")
        match = marker_pattern.search(line_without_newline)
        if match is None:
            output.append(line)
            index += 1
            continue
        prefix = line_without_newline[: match.start()].rstrip()
        if "$(" in prefix:
            # The substitution body is already inspected as the heredoc's
            # interpreter program. Preserve its launch command without an
            # unterminated outer assignment/quote.
            prefix = prefix.rsplit("$(", 1)[1]
        output.append(f"{prefix}\n")
        marker = match.group("marker")
        strip_tabs = match.group("strip") == "-"
        index += 1
        while index < len(lines):
            candidate = lines[index].rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == marker:
                break
            index += 1
        require(index < len(lines), "heredoc terminator is missing")
        index += 1
    return "".join(output)


def heredoc_has_runtime_mutation(
    script: str,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    for interpreter, body in heredoc_programs(script):
        if interpreter in {"python", "python3"}:
            if python_source_has_runtime_mutation(body):
                return True
        elif interpreter in SHELL_INTERPRETERS:
            if contains_runtime_mutation(
                body,
                seen_scripts,
                script_aliases,
                working_directory,
            ):
                return True
        else:
            # General-purpose stdin interpreters are not statically admitted.
            return True
    return False


def repository_script_has_runtime_mutation(
    target: str,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    normalized_target = target.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
    if script_aliases and normalized_target in script_aliases:
        target = script_aliases[normalized_target]
    elif script_aliases:
        for prefix, replacement in script_aliases.items():
            if prefix.endswith("/") and normalized_target.startswith(prefix):
                target = replacement + normalized_target.removeprefix(prefix)
                break
    if "${{" in target or "$" in target:
        return True
    relative_target = target.removeprefix("./")
    if Path(relative_target).is_absolute():
        return True
    if any(marker in relative_target for marker in "*?["):
        try:
            candidates = sorted(working_directory.glob(relative_target))
        except (OSError, ValueError):
            return True
        if not candidates:
            return True
        return any(
            repository_script_path_has_runtime_mutation(
                candidate,
                seen_scripts,
                script_aliases,
                working_directory,
            )
            for candidate in candidates
        )
    candidate = working_directory / relative_target
    if not candidate.exists():
        repository = os.environ.get("GITHUB_REPOSITORY")
        if not repository:
            repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
                "repository",
                "",
            )
        return target not in APPROVED_UNRESOLVED_SCRIPT_TARGETS.get(
            repository,
            frozenset(),
        )
    return repository_script_path_has_runtime_mutation(
        candidate,
        seen_scripts,
        script_aliases,
        working_directory,
    )


DYNAMIC_INVOCATION_CHARACTERS = frozenset("$`*?[]<>|;&(){}~")


def dynamic_invocation_token(token: str) -> bool:
    """Reject any argv token whose value is not a literal reviewed string.

    Read-only exemptions are keyed by an exact argument vector, so shell
    expansion, command substitution, response-file indirection, globs and
    redirections can never be part of an approved invocation.
    """

    if not token or token == "SUBSTITUTION" or token.isspace():
        return True
    if token.startswith("@"):
        return True
    if re.match(r"^\d*[<>]", token):
        return True
    return any(character in DYNAMIC_INVOCATION_CHARACTERS for character in token)


def approved_read_only_script_invocation(
    target: str,
    arguments: list[str],
    working_directory: Path,
) -> bool:
    if dynamic_invocation_token(target):
        return False
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    normalized = target.removeprefix("./")
    policy = APPROVED_READ_ONLY_SCRIPT_INVOCATIONS.get(repository, {}).get(
        normalized
    )
    if policy is None:
        return False
    expected_hash, allowed_arguments = policy
    candidate = working_directory / normalized
    try:
        root_lexical = ROOT.absolute()
        root_resolved = ROOT.resolve(strict=True)
        candidate_lexical = candidate.absolute()
        candidate_lexical.relative_to(root_lexical)

        current = candidate_lexical
        while True:
            if current.is_symlink():
                return False
            if current == root_lexical:
                break
            parent = current.parent
            if parent == current:
                return False
            current = parent

        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError):
        return False
    if resolved != candidate_lexical or not resolved.is_file():
        return False
    segment: list[str] = []
    for token in arguments:
        if token.isspace() or token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        if dynamic_invocation_token(token):
            return False
        segment.append(token)
    return (
        tuple(segment) in allowed_arguments
        and hashlib.sha256(resolved.read_bytes()).hexdigest() == expected_hash
    )


def repository_python_import_paths(
    source: str,
    current: Path,
    working_directory: Path,
) -> set[Path] | None:
    """Resolve repository-local Python imports for recursive policy scanning."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    targets: set[Path] = set()

    def add_module(base: Path, parts: list[str]) -> None:
        if not parts:
            return
        stem = base.joinpath(*parts)
        for candidate in (stem.with_suffix(".py"), stem / "__init__.py"):
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(ROOT.resolve())
            except (OSError, ValueError):
                continue
            if resolved.is_file() and not resolved.is_symlink():
                targets.add(resolved)
                return

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for base in (current.parent, working_directory, ROOT):
                    add_module(base, alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = current.parent
                for _ in range(node.level - 1):
                    base = base.parent
                module_parts = node.module.split(".") if node.module else []
                add_module(base, module_parts)
                if not module_parts:
                    for alias in node.names:
                        if alias.name != "*":
                            add_module(base, alias.name.split("."))
            elif node.module:
                for base in (current.parent, working_directory, ROOT):
                    module_parts = node.module.split(".")
                    add_module(base, module_parts)
                    for alias in node.names:
                        if alias.name != "*":
                            add_module(base, [*module_parts, *alias.name.split(".")])
    return targets


def repository_python_import_has_runtime_mutation(
    candidate: Path,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
    invoked_names: set[str],
) -> bool:
    """Scan import-time effects and bodies invoked through imported aliases."""

    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return True
    if resolved in seen_scripts:
        return False
    if not resolved.is_file() or resolved.is_symlink():
        return True
    try:
        source = resolved.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError):
        return True
    import_time_body: list[ast.stmt] = []
    for statement in tree.body:
        copied = deepcopy(statement)
        if isinstance(copied, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if copied.name not in invoked_names:
                copied.body = [ast.Pass()]
        import_time_body.append(copied)
    import_time = ast.Module(body=import_time_body, type_ignores=[])
    ast.fix_missing_locations(import_time)
    if python_source_has_runtime_mutation(ast.unparse(import_time)):
        return True
    nested_invocations = {
        child.func.id
        if isinstance(child.func, ast.Name)
        else child.func.attr
        for child in ast.walk(import_time)
        if isinstance(child, ast.Call)
        and isinstance(child.func, (ast.Name, ast.Attribute))
    }
    import_paths = repository_python_import_paths(
        source,
        resolved,
        working_directory,
    )
    if import_paths is None:
        return True
    return any(
        repository_python_import_has_runtime_mutation(
            imported,
            seen_scripts | {resolved},
            script_aliases,
            working_directory,
            nested_invocations,
        )
        for imported in import_paths
    )


def repository_javascript_import_paths(
    source: str,
    current: Path,
) -> set[Path] | None:
    """Resolve static repository-local JavaScript dependencies."""

    sanitized: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character in "\r\n":
                line_comment = False
                sanitized.append(character)
            else:
                sanitized.append(" ")
            index += 1
            continue
        if block_comment:
            if character == "*" and following == "/":
                sanitized.extend((" ", " "))
                block_comment = False
                index += 2
            else:
                sanitized.append(character if character in "\r\n" else " ")
                index += 1
            continue
        if escaped:
            sanitized.append(character)
            escaped = False
            index += 1
            continue
        if quote is not None:
            sanitized.append(character)
            if character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            sanitized.append(character)
            index += 1
            continue
        if character == "/" and following == "/":
            sanitized.extend((" ", " "))
            line_comment = True
            index += 2
            continue
        if character == "/" and following == "*":
            sanitized.extend((" ", " "))
            block_comment = True
            index += 2
            continue
        sanitized.append(character)
        index += 1
    if quote is not None or block_comment:
        return None
    code = "".join(sanitized)
    specifiers: set[str] = set()
    patterns = (
        r"\b(?:import|export)\s+(?:[^;\r\n]*?\s+from\s+)?"
        r"(['\"])(\.[^'\"\r\n]*)\1",
        r"\b(?:require|import)\s*\(\s*(['\"])(\.[^'\"\r\n]*)\1\s*\)",
    )
    for pattern in patterns:
        specifiers.update(match.group(2) for match in re.finditer(pattern, code))
    targets: set[Path] = set()
    for specifier in specifiers:
        if any(marker in specifier for marker in ("$", "?", "#", "\\")):
            return None
        base = current.parent / specifier
        candidates = [base]
        if base.suffix == "":
            candidates.extend(base.with_suffix(suffix) for suffix in (".js", ".mjs", ".cjs", ".json"))
            candidates.extend(base / f"index{suffix}" for suffix in (".js", ".mjs", ".cjs", ".json"))
        resolved_target: Path | None = None
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(ROOT.resolve())
            except (OSError, ValueError):
                continue
            if resolved.is_file() and not resolved.is_symlink():
                resolved_target = resolved
                break
        if resolved_target is None:
            return None
        if resolved_target.suffix.lower() != ".json":
            targets.add(resolved_target)
    return targets


def repository_script_path_has_runtime_mutation(
    candidate: Path,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if resolved in seen_scripts:
        return True
    suffix = resolved.suffix.lower()
    if suffix not in SCRIPT_SUFFIXES:
        return True
    source = resolved.read_text(encoding="utf-8")
    if resolved == Path(__file__).resolve():
        return False
    if resolved == RELEASE_VALIDATOR_PATH.resolve():
        validate_release_validator_operations(source)
        return False
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    expected_hash = APPROVED_COMPLEX_SCRIPT_SHA256.get(repository, {}).get(relative)
    if expected_hash is not None:
        if hashlib.sha256(source.encode()).hexdigest() != expected_hash:
            return True
        if relative in APPROVED_COMPLEX_SCRIPT_DEPENDENCY_SCAN.get(
            repository,
            frozenset(),
        ):
            dependency_aliases = dict(script_aliases or {})
            for variable in (
                "REPOSITORY_ROOT",
                "REPO_ROOT",
                "ROOT_DIR",
                "repository_root",
                "repo_root",
                "root_dir",
            ):
                if re.search(
                    rf"(?m)^{variable}=.*(?:dirname|git rev-parse --show-toplevel)",
                    source,
                ):
                    dependency_aliases[f"${variable}/"] = ""
                    dependency_aliases[f"${{{variable}}}/"] = ""
            return script_dependencies_have_runtime_mutation(
                source,
                dependency_aliases,
                working_directory,
            )
        return False
    if suffix == ".py":
        if python_source_has_runtime_mutation(source):
            return True
        import_paths = repository_python_import_paths(
            source,
            resolved,
            working_directory,
        )
        if import_paths is None:
            return True
        return any(
            repository_python_import_has_runtime_mutation(
                imported,
                seen_scripts | {resolved},
                script_aliases,
                working_directory,
                {
                    child.func.id
                    if isinstance(child.func, ast.Name)
                    else child.func.attr
                    for child in ast.walk(ast.parse(source))
                    if isinstance(child, ast.Call)
                    and isinstance(child.func, (ast.Name, ast.Attribute))
                },
            )
            for imported in import_paths
        )
    if suffix in {".cjs", ".js", ".mjs"}:
        if javascript_source_has_runtime_mutation(source):
            return True
        import_paths = repository_javascript_import_paths(source, resolved)
        if import_paths is None:
            return True
        return any(
            imported not in seen_scripts | {resolved}
            and repository_script_path_has_runtime_mutation(
                imported,
                seen_scripts | {resolved},
                script_aliases,
                working_directory,
            )
            for imported in import_paths
        )
    if suffix not in {".bash", ".sh"}:
        return True
    return contains_runtime_mutation(
        source,
        seen_scripts | {resolved},
        script_aliases,
        working_directory,
    )


def direct_repository_script_target(
    tokens: list[str],
    index: int,
    working_directory: Path,
) -> str | None:
    command_token = tokens[index]
    for prefix in ("$GITHUB_WORKSPACE/", "${GITHUB_WORKSPACE}/"):
        if command_token.startswith(prefix):
            command_token = command_token.removeprefix(prefix)
            break
    name = executable_name(command_token)
    arguments = tokens[index + 1 :]
    if name in {".", "source"}:
        for token in arguments:
            if shell_separator_token(token):
                break
            if not token.startswith("-"):
                return token
        return ""
    token = command_token
    if token.startswith(("./", "../")):
        return token
    if "$" in token and Path(token).suffix.lower() in SCRIPT_SUFFIXES:
        # Repository-script resolution will either bind an approved generated
        # path alias or reject the unresolved variable conservatively.
        return token
    if (
        "$" not in token
        and Path(token).suffix.lower() in SCRIPT_SUFFIXES
        and (working_directory / token).is_file()
    ):
        return token
    return None


def interpreter_module_target(
    tokens: list[str],
    index: int,
    working_directory: Path,
) -> str | None:
    if executable_name(tokens[index]) not in {"python", "python3"}:
        return None
    for option_index in range(index + 1, len(tokens)):
        token = tokens[option_index]
        if shell_separator_token(token):
            break
        if token != "-m":
            continue
        if option_index + 1 >= len(tokens) or "$" in tokens[option_index + 1]:
            return ""
        module = tokens[option_index + 1]
        candidates = (
            Path(*module.split(".")).with_suffix(".py"),
            Path(*module.split(".")) / "__main__.py",
        )
        for candidate in candidates:
            if (working_directory / candidate).is_file():
                return candidate.as_posix()
        return None
    return None


def interpreter_module_name(tokens: list[str], index: int) -> str | None:
    if executable_name(tokens[index]) not in {"python", "python3"}:
        return None
    for option_index in range(index + 1, len(tokens)):
        token = tokens[option_index]
        if shell_separator_token(token):
            break
        if token != "-m":
            continue
        if option_index + 1 >= len(tokens) or "$" in tokens[option_index + 1]:
            return ""
        return tokens[option_index + 1]
    return None


def interpreter_module_arguments(tokens: list[str], index: int) -> list[str]:
    for option_index in range(index + 1, len(tokens)):
        token = tokens[option_index]
        if shell_separator_token(token):
            break
        if token != "-m":
            continue
        if option_index + 1 >= len(tokens):
            return []
        return raw_command_arguments(tokens, option_index + 1)
    return []


def pytest_configured_targets(working_directory: Path) -> list[str] | None:
    """Return static pytest testpaths, or None when configuration is ambiguous."""

    candidates = (
        (ROOT / "pytest.ini", "pytest"),
        (ROOT / "setup.cfg", "tool:pytest"),
    )
    for path, section_name in candidates:
        if not path.exists():
            continue
        if not path.is_file() or path.is_symlink():
            return None
        source = path.read_text(encoding="utf-8")
        section = re.search(
            rf"(?ms)^\[{re.escape(section_name)}\]\s*(.*?)(?=^\[|\Z)",
            source,
        )
        if section is None:
            continue
        setting = re.search(
            r"(?m)^testpaths\s*=\s*([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)",
            section.group(1),
        )
        if setting is None:
            continue
        try:
            values = shlex.split(setting.group(1))
        except ValueError:
            return None
        if not values:
            return None
        for value in values:
            if (
                "$" in value
                or Path(value).is_absolute()
                or any(marker in value for marker in "*?[")
            ):
                return None
            try:
                resolved = (ROOT / value).resolve(strict=True)
                resolved.relative_to(ROOT.resolve())
            except (OSError, ValueError):
                return None
            if not resolved.is_dir() or resolved.is_symlink():
                return None
        return [os.path.relpath(ROOT / value, working_directory) for value in values]
    pyproject = ROOT / "pyproject.toml"
    if pyproject.exists():
        if not pyproject.is_file() or pyproject.is_symlink():
            return None
        source = pyproject.read_text(encoding="utf-8")
        section = re.search(
            r"(?ms)^\[tool\.pytest\.ini_options\]\s*(.*?)(?=^\[|\Z)",
            source,
        )
        if section is not None and re.search(r"(?m)^testpaths\s*=", section.group(1)):
            setting = re.search(
                r"(?ms)^testpaths\s*=\s*\[(.*?)\]",
                section.group(1),
            )
            if setting is None:
                return None
            targets = [
                match.group(2)
                for match in re.finditer(
                    r"(['\"])([^'\"\r\n]+)\1",
                    setting.group(1),
                )
            ]
            if not targets:
                return None
            if any(
                "$" in value
                or Path(value).is_absolute()
                or any(marker in value for marker in "*?[")
                for value in targets
            ):
                return None
            return [os.path.relpath(ROOT / value, working_directory) for value in targets]
    return []


def tracked_python_source_fingerprint() -> str | None:
    """Bind default test discovery to every tracked Python source byte."""

    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "-z", "*.py"],
            cwd=ROOT,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    excluded = {
        Path(__file__).resolve(),
        RELEASE_VALIDATOR_PATH.resolve(),
    }
    records: list[bytes] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = encoded.decode("utf-8")
            candidate = (ROOT / relative).resolve(strict=True)
            candidate.relative_to(ROOT.resolve())
        except (OSError, UnicodeDecodeError, ValueError):
            return None
        if candidate in excluded:
            continue
        if not candidate.is_file() or candidate.is_symlink():
            return None
        records.append(
            f"{relative}\0{hashlib.sha256(candidate.read_bytes()).hexdigest()}\n".encode()
        )
    if not records:
        return None
    return hashlib.sha256(b"".join(sorted(records))).hexdigest()


def test_runner_targets_have_runtime_mutation(
    module: str,
    arguments: list[str],
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    if module not in {"pytest", "unittest"}:
        return False
    option_values = {
        "--basetemp",
        "--confcutdir",
        "--ignore",
        "--ignore-glob",
        "--junitxml",
        "--log-file",
        "--maxfail",
        "--rootdir",
        "-k",
    }
    discovery_directories: frozenset[str] = frozenset()
    discovery_pattern = "test*.py"
    if module == "unittest":
        option_values |= {"--top-level-directory", "-t"}
        discovery_directories = frozenset({"--start-directory", "-s"})
    else:
        option_values |= {"-p"}
    targets: list[str] = []
    skip_value = False
    for argument_index, argument in enumerate(arguments):
        if skip_value:
            skip_value = False
            continue
        if argument in option_values:
            skip_value = True
            continue
        if argument in discovery_directories:
            skip_value = True
            if argument_index + 1 >= len(arguments):
                return True
            targets.append(arguments[argument_index + 1])
            continue
        if module == "unittest" and argument.startswith("--start-directory="):
            targets.append(argument.split("=", 1)[1])
            continue
        if module == "unittest" and argument in {"--pattern", "-p"}:
            if argument_index + 1 >= len(arguments):
                return True
            discovery_pattern = arguments[argument_index + 1]
            if (
                not discovery_pattern
                or "$" in discovery_pattern
                or "/" in discovery_pattern
                or "\\" in discovery_pattern
            ):
                return True
            skip_value = True
            continue
        if module == "unittest" and argument.startswith("--pattern="):
            discovery_pattern = argument.split("=", 1)[1]
            if (
                not discovery_pattern
                or "$" in discovery_pattern
                or "/" in discovery_pattern
                or "\\" in discovery_pattern
            ):
                return True
            continue
        if argument == "discover" or argument.startswith("-"):
            continue
        targets.append(argument.split("::", 1)[0])
    default_discovery = not targets
    if default_discovery:
        configured = pytest_configured_targets(working_directory) if module == "pytest" else []
        if configured is None:
            return True
        targets.extend(configured or ["."])
    for target in targets:
        if not target or "$" in target or any(marker in target for marker in "*?["):
            return True
        normalized = target.removeprefix("./")
        candidates = [working_directory / normalized]
        if (
            normalized not in {".", ".."}
            and "/" not in normalized
            and not normalized.endswith(".py")
        ):
            candidates.extend(
                (
                    working_directory / Path(*normalized.split(".")).with_suffix(".py"),
                    working_directory / Path(*normalized.split(".")) / "__init__.py",
                )
            )
        resolved_targets: list[Path] = []
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(ROOT.resolve())
            except (OSError, ValueError):
                continue
            if resolved.is_file() and not resolved.is_symlink():
                resolved_targets = [resolved]
                break
            if resolved.is_dir() and not resolved.is_symlink():
                patterns = {discovery_pattern}
                if module == "pytest":
                    patterns |= {"*_test.py", "conftest.py"}
                discovered = sorted(
                    {
                        item
                        for pattern in patterns
                        for item in resolved.rglob(pattern)
                    }
                )
                if discovered and all(
                    item.is_file() and not item.is_symlink()
                    for item in discovered
                ):
                    resolved_targets = discovered
                break
        if not resolved_targets:
            return True
        if any(
            repository_script_path_has_runtime_mutation(
                resolved_target,
                seen_scripts,
                script_aliases,
                working_directory,
            )
            for resolved_target in resolved_targets
        ):
            if default_discovery:
                repository = os.environ.get("GITHUB_REPOSITORY")
                if not repository:
                    repository = json.loads(
                        CONTRACT_PATH.read_text(encoding="utf-8")
                    ).get("repository", "")
                expected = APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256.get(
                    repository
                )
                if (
                    expected is not None
                    and working_directory.resolve() == ROOT.resolve()
                    and tracked_python_source_fingerprint() == expected
                ):
                    continue
            return True
    return False


def script_dependencies_have_runtime_mutation(
    script: str,
    script_aliases: dict[str, str] | None,
    working_directory: Path,
    trusted_repository_scripts: frozenset[str] = frozenset(),
) -> bool:
    def manifest_trust(target: str, index: int) -> bool | None:
        """Trust pinned Python only when its import path is isolated."""

        normalized = target.removeprefix("./")
        if normalized not in trusted_repository_scripts:
            return None
        if Path(normalized).suffix.lower() != ".py":
            return False
        if executable_name(tokens[index]) not in {"python", "python3"}:
            return False
        for option_index in range(index + 1, len(tokens)):
            option = tokens[option_index]
            if option in {"|", "||", "&&", ";", "&", "{", "}"}:
                break
            if option.removeprefix("./") == normalized:
                return "-I" in tokens[index + 1 : option_index]
        return False

    tokens = shell_tokens(script)
    for index in command_indexes(tokens):
        raw_tail = raw_command_arguments(tokens, index)
        interpreter_target = interpreter_script_target(tokens, index)
        if interpreter_target is not None:
            invocation_arguments: list[str] = []
            for target_index, token in enumerate(raw_tail):
                if (
                    token.removeprefix("./")
                    == interpreter_target.removeprefix("./")
                ):
                    invocation_arguments = raw_tail[target_index + 1 :]
                    break
            trust = manifest_trust(interpreter_target, index)
            if trust is False:
                return True
            if (
                trust is None
                and not approved_read_only_script_invocation(
                    interpreter_target,
                    invocation_arguments,
                    working_directory,
                )
                and repository_script_has_runtime_mutation(
                    interpreter_target,
                    set(),
                    script_aliases,
                    working_directory,
                )
            ):
                return True

        module_target = interpreter_module_target(
            tokens,
            index,
            working_directory,
        )
        if module_target is not None:
            trust = manifest_trust(module_target, index)
            if trust is False:
                return True
            if (
                trust is None
                and not approved_read_only_script_invocation(
                    module_target,
                    interpreter_module_arguments(tokens, index),
                    working_directory,
                )
                and repository_script_has_runtime_mutation(
                    module_target,
                    set(),
                    script_aliases,
                    working_directory,
                )
            ):
                return True

        direct_target = direct_repository_script_target(
            tokens,
            index,
            working_directory,
        )
        if direct_target is not None:
            trust = manifest_trust(direct_target, index)
            if trust is False:
                return True
            if (
                trust is None
                and not approved_read_only_script_invocation(
                    direct_target,
                    raw_tail,
                    working_directory,
                )
                and repository_script_has_runtime_mutation(
                    direct_target,
                    set(),
                    script_aliases,
                    working_directory,
                )
            ):
                return True
    return False


def inline_interpreter_payload_has_runtime_mutation(
    interpreter: str,
    payload: str,
    seen_scripts: set[Path] | None = None,
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    if "$" in payload or "SUBSTITUTION" in payload:
        return True
    if interpreter in {"python", "python3"}:
        return python_source_has_runtime_mutation(payload)
    if interpreter == "node":
        return javascript_source_has_runtime_mutation(payload)
    if interpreter in SHELL_INTERPRETERS:
        return contains_runtime_mutation(
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        )
    # Perl, PHP, and Ruby inline programs are not statically admitted.
    return True


def shell_tokens_have_network_device_redirect(tokens: list[str]) -> bool:
    """Recognize Bash's socket-opening /dev/tcp and /dev/udp redirections."""

    redirect = re.compile(
        r"^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?"
        r"(?:<>|>>?|<|&>>?|>\|)(?P<path>.*)$"
    )
    variable = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
    def resolve_path(path: str, bindings: dict[str, str]) -> str:
        def replacement(match: re.Match[str]) -> str:
            return bindings.get(match.group(1) or match.group(2), match.group(0))

        return variable.sub(replacement, path)

    for index, token in enumerate(tokens):
        match = redirect.match(token)
        if match is None:
            continue
        path = match.group("path")
        if not path and index + 1 < len(tokens):
            path = tokens[index + 1]
        resolved = resolve_path(path, shell_command_bindings(tokens, index))
        if resolved.startswith(("/dev/tcp/", "/dev/udp/")):
            return True
        approved_dynamic = resolved in {"$GITHUB_OUTPUT", "${GITHUB_OUTPUT}"} or (
            resolved.startswith(("$RUNNER_TEMP/", "${RUNNER_TEMP}/"))
        )
        if "$" in resolved and not approved_dynamic:
            # An unresolved redirect target can synthesize /dev/tcp or /dev/udp.
            # The release workflow only needs runner-owned output paths.
            return True
    return False


def inline_interpreter_payload_has_runtime_contact(
    interpreter: str,
    payload: str,
) -> bool:
    """Fail closed on any unproved contact from an inline program."""

    if interpreter in SCRIPT_INTERPRETERS:
        # Plan-only intent admits one separately operation-verified repository
        # validator, not arbitrary inline programs in Turing-complete languages.
        return True
    if interpreter in SHELL_INTERPRETERS:
        return contains_runtime_command(payload) or contains_runtime_mutation(payload)
    # Perl, PHP, and Ruby inline programs are not statically admitted.
    return True


def package_manager_payloads(
    name: str,
    arguments: list[str],
    seen_scripts: set[Path],
    working_directory: Path,
) -> tuple[list[str], Path] | None:
    """Resolve repository-owned package scripts, or fail closed with None."""

    directory_options = {"--cwd", "--dir", "--prefix", "-c"}
    selector_options = {"--filter", "--workspace", "-w"}
    option_value_names = directory_options | selector_options | {"--config"}
    harmless_global_flags = {
        "--color",
        "--help",
        "--no-color",
        "--silent",
        "--version",
        "--yes",
        "-h",
        "-s",
        "-v",
        "-y",
    }
    def safe_directory(base: Path, value: str) -> Path | None:
        if not value or "$" in value or "${{" in value or Path(value).is_absolute():
            return None
        try:
            candidate = (base / value).resolve(strict=True)
            candidate.relative_to(ROOT.resolve())
        except (OSError, ValueError):
            return None
        return candidate if candidate.is_dir() and not candidate.is_symlink() else None

    def selected_workspace(selector: str) -> Path | None:
        direct = safe_directory(ROOT, selector)
        candidates: set[Path] = set()
        if direct is not None and (direct / "package.json").is_file():
            candidates.add(direct)
        for pattern in ("*/package.json", "*/*/package.json", "*/*/*/package.json"):
            for package in ROOT.glob(pattern):
                if package.is_symlink() or "node_modules" in package.parts:
                    continue
                try:
                    document = json.loads(package.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(document, dict) and document.get("name") == selector:
                    candidates.add(package.parent.resolve())
        return next(iter(candidates)) if len(candidates) == 1 else None

    effective_directory = working_directory
    selector: str | None = None
    command: str | None = None
    command_index: int | None = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        if token == "SUBSTITUTION" or "$" in token:
            return None
        lower_token = token.lower()
        option_name = lower_token.split("=", 1)[0]
        if option_name in option_value_names:
            if "=" in token:
                value = token.split("=", 1)[1]
            else:
                if index + 1 >= len(arguments):
                    return None
                value = arguments[index + 1]
                index += 1
            if option_name in directory_options:
                resolved = safe_directory(effective_directory, value)
                if resolved is None:
                    return None
                effective_directory = resolved
            elif option_name in selector_options:
                selector = value
            else:
                # An arbitrary configuration file can change command parsing.
                return None
            index += 1
            continue
        if token.startswith("-"):
            if lower_token in harmless_global_flags:
                index += 1
                continue
            return None
        command = token
        command_index = index
        break
    if selector is not None:
        selected_directory = selected_workspace(selector)
        if selected_directory is None:
            return None
        effective_directory = selected_directory
    if command is None:
        return [], effective_directory
    lower = command.lower()
    if lower in {
        "access",
        "adduser",
        "deprecate",
        "dist-tag",
        "dlx",
        "hook",
        "login",
        "logout",
        "owner",
        "publish",
        "star",
        "team",
        "token",
        "unpublish",
        "unstar",
        "version",
    }:
        return None
    package_path = effective_directory / "package.json"
    if not package_path.is_file() or package_path.is_symlink():
        return None
    try:
        document = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    scripts = document.get("scripts", {}) if isinstance(document, dict) else {}
    if not isinstance(scripts, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in scripts.items()
    ):
        return None
    executable_command = lower
    if lower == "exec" and name in {"bun", "pnpm", "yarn"}:
        if command_index is None:
            return None
        executable_command = ""
        for token in arguments[command_index + 1 :]:
            if token in {"|", "||", "&&", ";", "&", "{", "}"}:
                break
            if token == "SUBSTITUTION" or "$" in token or token.startswith("-"):
                return None
            executable_command = executable_name(token).lower()
            break
        if not executable_command:
            return None
    if name in {"npx", "bunx"} or lower == "exec":
        dependencies: set[str] = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            values = document.get(field, {})
            if isinstance(values, dict):
                dependencies.update(
                    key for key in values if isinstance(key, str)
                )
        safe_executables = {"eslint", "playwright", "tsc", "vite", "vitest"}
        declared_names = {
            "playwright": {"@playwright/test", "playwright"},
        }.get(executable_command, {executable_command})
        return (
            ([], effective_directory)
            if executable_command in safe_executables
            and bool(declared_names & dependencies)
            else None
        )
    script_name: str | None = None
    if lower in {"run", "run-script"}:
        if command_index is None:
            return None
        for token in arguments[command_index + 1 :]:
            if token in {"|", "||", "&&", ";", "&", "{", "}"}:
                break
            lower_token = token.lower()
            if lower_token in option_value_names or any(
                lower_token.startswith(f"{option}=")
                for option in option_value_names
                if option.startswith("--")
            ):
                return None
            if not token.startswith("-"):
                script_name = token
                break
        if script_name is None:
            return None
    elif name in {"bun", "pnpm", "yarn"} and lower not in {
        "add",
        "audit",
        "config",
        "exec",
        "install",
        "pack",
        "remove",
        "run",
        "run-script",
        "set",
        "upgrade",
    }:
        script_name = command
    elif lower in {"restart", "start", "stop", "test"}:
        script_name = lower
    if script_name is not None:
        selected = [f"pre{script_name}", script_name, f"post{script_name}"]
        if script_name not in scripts:
            return None
    elif lower in {"ci", "install"}:
        if "--ignore-scripts" in arguments:
            return [], effective_directory
        selected = ["preinstall", "install", "postinstall", "prepublish", "prepare"]
    elif lower == "pack":
        selected = ["prepack", "prepare", "postpack"]
    else:
        return [], effective_directory
    payloads: list[str] = []
    for selected_name in selected:
        payload = scripts.get(selected_name)
        if payload is None:
            continue
        sentinel = package_path.with_name(
            f"{package_path.name}.codestra-script-{selected_name}"
        )
        if sentinel in seen_scripts:
            return None
        seen_scripts.add(sentinel)
        payloads.append(payload)
    return payloads, effective_directory


def contains_runtime_command(script: str) -> bool:
    if heredoc_has_runtime_mutation(script, set(), None, ROOT):
        return True
    for interpreter, body in heredoc_programs(script):
        if inline_interpreter_payload_has_runtime_contact(interpreter, body):
            return True
    shell_script = shell_without_heredoc_bodies(script)
    parsed_substitutions = shell_command_substitutions(shell_script)
    if parsed_substitutions is None:
        return True
    substitutions, shell_script = parsed_substitutions
    if any(contains_runtime_command(payload) for payload in substitutions):
        return True
    tokens = shell_tokens(shell_script)
    if shell_tokens_have_network_device_redirect(tokens):
        return True
    for index in command_indexes(tokens):
        bindings = shell_command_bindings(tokens, index)
        command_token = resolved_command_token(tokens[index], bindings)
        name = executable_name(command_token)
        raw_arguments = raw_command_arguments(tokens, index)
        arguments = command_arguments(tokens, index)
        if name not in RELEASE_INTENT_ALLOWED_COMMANDS:
            # Release intent is an exact, plan-only evidence workflow. Unknown
            # executables are runtime-capable until explicitly reviewed here.
            return True
        if name == "gh" and (
            bindings
            or tuple(raw_arguments) not in RELEASE_INTENT_ALLOWED_GH_API
        ):
            return True
        if name == "python3" and interpreter_script_target(tokens, index) != (
            ".codestra/validate-release-intent.py"
        ):
            return True
        if command_token_has_dynamic_executable(command_token):
            return True
        if command_token == "SUBSTITUTION":
            return True
        if absolute_executable_is_unproved(command_token):
            return True
        if name == "xargs":
            payload = xargs_payload(raw_arguments)
            if payload is None or payload and (
                contains_runtime_mutation(payload)
                or command_consumes_pipeline(tokens, index)
                and contains_runtime_command(payload)
            ):
                return True
        if name == "trap" and raw_arguments and contains_runtime_command(raw_arguments[0]):
            return True
        if name == "openssl" and "s_client" in arguments:
            return True
        if name == "git" and (
            any(key.upper().startswith("GIT_") for key in bindings)
            or any("ext::" in token.lower() for token in raw_arguments)
        ):
            return True
        if (
            name in RUNTIME_TOOLS
            or name.lower() in GENERIC_NETWORK_CLIENTS
            or name in SHELL_WRAPPERS
            or name.endswith("deploy_immutable")
            or name.endswith("apply-plan.sh")
            or api_client_has_mutating_operation(name, arguments)
        ):
            return True
        if (
            name in (SHELL_INTERPRETERS | SCRIPT_INTERPRETERS)
            and interpreter_payload(tokens, index) is None
            and any(
                token == "<<<" or token.startswith("<<<")
                for token in raw_arguments
            )
        ):
            return True
        payload = interpreter_payload(tokens, index)
        if payload is not None and inline_interpreter_payload_has_runtime_contact(
            name, payload
        ):
            return True
    return False


def contains_runtime_mutation(
    script: str,
    seen_scripts: set[Path] | None = None,
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    if seen_scripts is None:
        seen_scripts = set()
    if "$GITHUB_ENV" in script and re.search(
        r"\b(?:BASH_ENV|ENV|LD_LIBRARY_PATH|LD_PRELOAD|NODE_OPTIONS|PATH|"
        r"PERL5OPT|PYTHONHOME|PYTHONINSPECT|PYTHONPATH|PYTHONSTARTUP|RUBYOPT)\s*=",
        script,
        re.IGNORECASE,
    ):
        # Persisted shell startup or executable-resolution changes affect
        # later steps whose literal commands can otherwise look harmless.
        return True
    if heredoc_has_runtime_mutation(
        script,
        seen_scripts,
        script_aliases,
        working_directory,
    ):
        return True
    shell_script = shell_without_heredoc_bodies(script)
    parsed_substitutions = shell_command_substitutions(shell_script)
    if parsed_substitutions is None:
        return True
    substitutions, shell_script = parsed_substitutions
    if any(
        contains_runtime_mutation(
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        )
        for payload in substitutions
    ):
        return True
    tokens = shell_tokens(shell_script)
    if shell_tokens_have_network_device_redirect(tokens):
        return True
    for index in command_indexes(tokens):
        bindings = shell_command_bindings(tokens, index)
        if any(key.upper() in EXECUTABLE_STARTUP_ENV for key in bindings):
            return True
        command_token = resolved_command_token(tokens[index], bindings)
        name = executable_name(command_token)
        raw_tail = raw_command_arguments(tokens, index)
        tail = [executable_name(token) for token in raw_tail]
        lower_name = name.lower()
        payload = interpreter_payload(tokens, index)
        if payload is not None and inline_interpreter_payload_has_runtime_mutation(
            name,
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        ):
            return True
        target = interpreter_script_target(tokens, index)
        if target is not None:
            invocation_arguments: list[str] = []
            for target_index, token in enumerate(raw_tail):
                if token.removeprefix("./") == target.removeprefix("./"):
                    invocation_arguments = raw_tail[target_index + 1 :]
                    break
            if not approved_read_only_script_invocation(
                target,
                invocation_arguments,
                working_directory,
            ) and repository_script_has_runtime_mutation(
                target,
                seen_scripts,
                script_aliases,
                working_directory,
            ):
                return True
        module_name = interpreter_module_name(tokens, index)
        module_target = interpreter_module_target(tokens, index, working_directory)
        module_arguments = interpreter_module_arguments(tokens, index)
        if module_name is not None and test_runner_targets_have_runtime_mutation(
            module_name,
            module_arguments,
            seen_scripts,
            script_aliases,
            working_directory,
        ):
            return True
        if module_name is not None and (
            not module_name
            or module_target is None
            and module_name not in SAFE_EXTERNAL_PYTHON_MODULES
        ):
            # Installed module entry points can execute arbitrary startup and
            # migration logic. Only explicitly read-only standard/tooling
            # modules may remain outside the repository dependency closure.
            return True
        if (
            module_target is not None
            and not approved_read_only_script_invocation(
                module_target,
                module_arguments,
                working_directory,
            )
            and repository_script_has_runtime_mutation(
                module_target,
                seen_scripts,
                script_aliases,
                working_directory,
            )
        ):
            return True
        resolved_tokens = tokens
        if command_token != tokens[index]:
            resolved_tokens = tokens.copy()
            resolved_tokens[index] = command_token
        direct_target = direct_repository_script_target(
            resolved_tokens,
            index,
            working_directory,
        )
        if direct_target is not None and repository_script_has_runtime_mutation(
            direct_target,
            seen_scripts,
            script_aliases,
            working_directory,
        ) and not approved_read_only_script_invocation(
            direct_target,
            raw_tail,
            working_directory,
        ):
            return True
        if command_token_has_dynamic_executable(command_token) and direct_target is None:
            return True
        if command_token == "SUBSTITUTION":
            return True
        if absolute_executable_is_unproved(command_token):
            return True
        unproved_stdin = (
            command_consumes_pipeline(tokens, index)
            or any(token == "<<<" or token.startswith("<<<") for token in raw_tail)
        ) and payload is None and target is None and module_target is None
        if unproved_stdin and name in (SHELL_INTERPRETERS | SCRIPT_INTERPRETERS):
            return True
        if name in SHELL_WRAPPERS:
            return True
        if name in {"alias", "unalias"} or (
            name == "shopt" and "expand_aliases" in raw_tail
        ):
            # Shell aliases can replace an apparently harmless command token
            # after static parsing, so alias manipulation is not read-only.
            return True
        if name in {"make", "just", "task"}:
            return True
        if name in {"bun", "bunx", "npm", "npx", "pnpm", "yarn"}:
            package_resolution = package_manager_payloads(
                name,
                raw_tail,
                seen_scripts,
                working_directory,
            )
            if package_resolution is None:
                return True
            package_payloads, package_directory = package_resolution
            if any(
                contains_runtime_mutation(
                    package_payload,
                    seen_scripts,
                    script_aliases,
                    package_directory,
                )
                for package_payload in package_payloads
            ):
                return True
        if name == "find" and any(
            token.lower() in {"-exec", "-execdir", "-ok", "-okdir"}
            or token == "SUBSTITUTION"
            or "$" in token
            for token in raw_tail
        ):
            # Shell expansion can supply an action token such as -exec.
            # Unresolved arguments cannot prove a find expression read-only.
            return True
        if name == "xargs":
            payload = xargs_payload(raw_tail)
            if payload is None or payload and (
                contains_runtime_mutation(
                    payload,
                    seen_scripts,
                    script_aliases,
                    working_directory,
                )
                or command_consumes_pipeline(tokens, index)
                and contains_runtime_command(payload)
            ):
                return True
        if name == "trap" and raw_tail and contains_runtime_mutation(
            raw_tail[0],
            seen_scripts,
            script_aliases,
            working_directory,
        ):
            return True
        if (
            name.lower() in GENERIC_NETWORK_CLIENTS
            or name == "openssl" and "s_client" in tail
        ) and (
            command_consumes_pipeline(tokens, index)
            or any(re.match(r"^(?:\\d+)?<", token) for token in raw_tail)
        ):
            return True
        if name == "git" and (
            any(key.upper().startswith("GIT_") for key in bindings)
            or any("ext::" in token.lower() for token in raw_tail)
        ):
            return True
        if name in {"ansible-playbook", "chroot", "script", "scp", "ssh"}:
            return True
        if name in {"helm", "kubectl", "terraform", "tofu"} and (
            runtime_cli_operation_is_dynamic(name, raw_tail)
        ):
            return True
        if name == "kubectl" and (
            any(item in KUBECTL_MUTATIONS for item in tail)
            or any(
                tail[position : position + 2] == ["auth", "reconcile"]
                for position in range(len(tail) - 1)
            )
        ):
            return True
        if name == "helm" and any(item in HELM_MUTATIONS for item in tail):
            return True
        if name in {"terraform", "tofu"} and (
            any(item in TERRAFORM_MUTATIONS for item in tail)
            or "state" in tail and any(item in {"mv", "push", "rm"} for item in tail)
        ):
            return True
        if name in {"docker", "podman"} and "compose" in tail and any(
            item in CONTAINER_MUTATIONS for item in tail
        ):
            return True
        if name in {"docker", "podman"} and (
            not raw_tail
            or "$" in raw_tail[0]
            or raw_tail[0] == "SUBSTITUTION"
        ):
            # A computed Docker/Podman operation can expand to any lifecycle
            # or publication command and cannot be classified read-only.
            return True
        if name in {"docker", "podman"} and any(
            item
            in {
                *CONTAINER_MUTATIONS,
                "create",
                "pause",
                "rename",
                "unpause",
                "update",
            }
            for item in tail[:2]
        ):
            return True
        if name in {"docker", "podman"} and any(
            item in {"exec", "run"} for item in tail
        ):
            # The image entrypoint or nested executable can perform an
            # arbitrary runtime mutation and is not statically provable here.
            return True
        if name in {"docker", "podman"} and (
            "stack" in tail
            and any(item in {"deploy", "rm"} for item in tail)
            or "service" in tail
            and any(
                item in {"create", "rm", "rollback", "scale", "update"}
                for item in tail
            )
            or "swarm" in tail
            and any(item in {"init", "join", "leave", "update"} for item in tail)
        ):
            return True
        if api_client_has_mutating_operation(name, tail):
            return True
        if (
            name.endswith("deploy_immutable")
            or name.endswith("apply-plan.sh")
            or lower_name.startswith("deploy_")
            and lower_name.endswith((".py", ".sh"))
            and any(item in {"apply", "apply-and-issue", "deploy", "rollback"} for item in tail)
            or "reconcile" in lower_name
            and any(item in {"apply", "apply-and-issue", "deploy"} for item in tail)
        ):
            return True
    return False


def option_value(tokens: list[str], names: set[str]) -> str | None:
    for index, token in enumerate(tokens):
        lower = token.lower()
        if lower in names:
            return tokens[index + 1].lower() if index + 1 < len(tokens) else ""
        for name in names:
            if lower.startswith(f"{name}="):
                return lower.split("=", 1)[1]
            if name in {"-x", "-m"} and lower.startswith(name) and len(lower) > 2:
                return lower[2:]
    return None


def api_client_has_mutating_operation(name: str, tail: list[str]) -> bool:
    """Classify explicit write modes for generic API and cloud clients."""

    lower_name = name.lower()
    lower_tail = [token.lower() for token in tail]
    if lower_name in {"awk", "gawk", "mawk", "nawk"}:
        return any(
            "SUBSTITUTION" in token
            or re.search(
                r"\bsystem\s*\(|\|\s*getline\b|\b(?:print|printf)\b[^;{}]*\|",
                token,
            )
            is not None
            for token in tail
        )
    if lower_name == "git":
        index = 0
        while index < len(lower_tail) and lower_tail[index].startswith("-"):
            option = lower_tail[index]
            raw_option = tail[index]
            if raw_option == "-c" or raw_option.startswith("-c") and len(raw_option) > 2:
                # Per-invocation configuration can install shell aliases or
                # redirect transports and helper executables.
                return True
            if raw_option == "-C" or option in {"--git-dir", "--work-tree", "--namespace"}:
                index += 2
                continue
            if any(
                option.startswith(f"{prefix}=")
                for prefix in ("--git-dir", "--work-tree", "--namespace")
            ):
                index += 1
                continue
            if option in {
                "--bare",
                "--no-pager",
                "--no-replace-objects",
                "--literal-pathspecs",
                "--glob-pathspecs",
                "--noglob-pathspecs",
                "--icase-pathspecs",
            }:
                index += 1
                continue
            return True
        if index >= len(lower_tail):
            return False
        command = lower_tail[index]
        if command == "config":
            return not any(
                token in {
                    "--get",
                    "--get-all",
                    "--get-regexp",
                    "--get-urlmatch",
                    "--list",
                    "--show-origin",
                    "--show-scope",
                    "get",
                    "get-all",
                    "get-regexp",
                    "get-urlmatch",
                    "list",
                }
                for token in lower_tail[index + 1 :]
            )
        read_only_or_local = {
            "archive",
            "branch",
            "cat-file",
            "check-attr",
            "check-ignore",
            "checkout",
            "diff",
            "diff-index",
            "diff-tree",
            "fetch",
            "grep",
            "hash-object",
            "log",
            "ls-files",
            "ls-remote",
            "merge-base",
            "rev-list",
            "rev-parse",
            "show",
            "show-ref",
            "status",
            "tag",
            "worktree",
        }
        # Unknown subcommands may be configured shell aliases; remote writers
        # such as push are intentionally outside this allowlist.
        return command not in read_only_or_local
    if lower_name in {"curl", "wget"}:
        if lower_name == "curl" and any(
            token == "-K"
            or lower == "--config"
            or token.startswith("-K") and len(token) > 2
            or lower.startswith("--config=")
            for token, lower in zip(tail, lower_tail, strict=True)
        ):
            return True
        method = option_value(lower_tail, {"--method", "--request", "-m", "-x"})
        if method is not None and method not in {"get", "head", "options", "trace"}:
            return True
        return any(
            lower in HTTP_MUTATION_FLAGS
            or any(
                lower.startswith(f"{flag}=")
                for flag in HTTP_MUTATION_FLAGS
                if flag.startswith("--")
            )
            or lower.startswith("-d") and len(token) > 2
            or token.startswith(("-F", "-T"))
            or lower.startswith("--post-")
            for token, lower in zip(tail, lower_tail, strict=True)
        )
    if lower_name == "gh" and lower_tail:
        inherited_value_options = {"--config-dir", "--hostname", "--repo", "-r"}
        index = 0
        while index < len(lower_tail) and lower_tail[index].startswith("-"):
            option = lower_tail[index]
            if option in inherited_value_options:
                index += 2
                continue
            if any(
                option.startswith(f"{name}=")
                for name in inherited_value_options
                if name.startswith("--")
            ) or option.startswith("-r") and len(option) > 2:
                index += 1
                continue
            return True
        arguments = lower_tail[index:]
        if not arguments:
            return False
        if arguments[0] == "api":
            method = option_value(arguments[1:], {"--method", "-x"})
            return (
                method not in {None, "get"}
                or any(
                    token in {"--field", "--input", "--raw-field", "-f"}
                    or token.startswith(
                        ("--field=", "--input=", "--raw-field=", "-f=")
                    )
                    for token in arguments[1:]
                )
            )
        read_only_commands = {
            ("attestation", "verify"),
            ("auth", "setup-git"),
            ("auth", "status"),
            ("cache", "list"),
            ("issue", "list"),
            ("issue", "status"),
            ("issue", "view"),
            ("pr", "checks"),
            ("pr", "diff"),
            ("pr", "list"),
            ("pr", "status"),
            ("pr", "view"),
            ("release", "download"),
            ("release", "list"),
            ("release", "view"),
            ("repo", "list"),
            ("repo", "view"),
            ("run", "download"),
            ("run", "list"),
            ("run", "view"),
            ("run", "watch"),
            ("secret", "list"),
            ("variable", "get"),
            ("variable", "list"),
            ("workflow", "list"),
            ("workflow", "view"),
        }
        return tuple(arguments[:2]) not in read_only_commands
    if lower_name in {"aws", "az", "doctl", "gcloud"}:
        # These general-purpose clients can mutate through non-verb operations
        # (for example, `aws s3 cp`). No native workflow currently needs a
        # cloud CLI for read-only evidence, so any invocation fails closed.
        return True
    return False


def contains_runtime_action(step: dict[str, Any]) -> bool:
    value = step.get("uses")
    if not isinstance(value, str):
        return False
    normalized = value.split(" #", 1)[0].strip().lower()
    if normalized.startswith("actions/github-script@"):
        inputs = step.get("with")
        if not isinstance(inputs, dict) or not isinstance(inputs.get("script"), str):
            return True
        script = re.sub(r"\?\s*\.", ".", inputs["script"].lower())
        member_script = re.sub(r"\s*\.\s*", ".", script)
        if any(
            marker in script
            for marker in (
                "child_process",
                "createworkflowdispatch",
                "repositorydispatch",
                "workflow_dispatch",
                "/dispatches",
                "exec.exec",
                "exec.getexecoutput",
                "fetch(",
            )
        ):
            return True
        if re.search(
            r"\bgithub(?:\s*\.\s*[a-z_$][a-z0-9_$]*)*\s*\[",
            script,
        ) or re.search(
            r"\b(?:const|let|var)\s*\{[^}]+\}\s*=\s*github\b",
            script,
        ) or re.search(
            r"\b(?:const|let|var)\s+[a-z_$][a-z0-9_$]*\s*=\s*github\b",
            script,
        ) or re.search(
            r"\bobject\s*\.\s*(?:assign|create)\s*\([^)]*\bgithub\b",
            script,
            re.DOTALL,
        ) or re.search(
            r"\bnew\s+proxy\s*\(\s*github\b|\.\.\.\s*github\b",
            script,
        ) or (
            re.search(r"\bgithub\b", script) is not None
            and re.search(
                r"\b(?:object\s*\.\s*(?:assign|create)|new\s+proxy|"
                r"reflect\s*\.\s*get)\b",
                script,
            )
            is not None
        ):
            # Bracket access and destructuring can hide REST, request, or
            # GraphQL writers from property-name inspection.
            return True
        if re.search(
            r"github(?:\.rest)?(?:\.[a-z0-9_]+)+\."
            r"(?:add|approve|cancel|create|delete|disable|dispatch|enable|lock|merge|"
            r"remove|replace|request|rerun|set|unlock|update|upload)[a-z0-9_]*\b",
            member_script,
        ):
            # A mutating REST method can be assigned to another identifier
            # before invocation, so the property reference itself is unsafe.
            return True
        request_calls = list(re.finditer(r"github\.request\s*\(", member_script))
        if re.search(
            r"github\s*(?:\.\s*graphql\b|\[\s*['\"]graphql['\"]\s*\])",
            script,
        ):
            # GraphQL documents and interpolated fragments cannot be proved
            # read-only, and bracket access can alias the callable.
            return True
        if "github.request" in member_script and not request_calls:
            # Reject callable aliases such as ``const write = github.request``.
            return True
        return any(
            re.match(
                r"\s*['\"`]\s*(?:get|head)\s+",
                member_script[match.end() :],
            )
            is None
            for match in request_calls
        )
    return (
        normalized.startswith("./")
        or "${{" in normalized
        or any(marker in normalized for marker in MUTATING_ACTION_MARKERS)
        or not any(
            normalized.startswith(prefix) for prefix in SAFE_NATIVE_ACTION_PREFIXES
        )
    )


def contains_image_publication(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and isinstance(inputs, dict):
        normalized = uses.split(" #", 1)[0].strip().lower()
        if normalized.startswith("docker/build-push-action@"):
            if inputs.get("push", False) not in {False, "false"}:
                return True
            outputs = inputs.get("outputs")
            if outputs is None:
                return False
            if not isinstance(outputs, str) or "${{" in outputs:
                return True
            for output in outputs.splitlines():
                fields = {
                    key.strip().lower(): value.strip().lower()
                    for field in output.split(",")
                    if "=" in field
                    for key, value in [field.split("=", 1)]
                }
                if fields.get("type") == "registry" or (
                    fields.get("type") == "image"
                    and fields.get("push") not in {None, "false"}
                ):
                    return True
            return False
        if normalized.startswith("actions/attest-build-provenance@"):
            return inputs.get("push-to-registry", False) not in {False, "false"}
    run = str(step.get("run", ""))
    if re.search(
        r"(?ms)^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*"
        r"(?:\(\s*\))?\s*\{.*?\b(?:docker|podman)\b",
        run,
    ):
        # A shell function can forward or synthesize a later `push` operation,
        # while token inspection sees only the function invocation. Without a
        # shell AST, a container CLI inside a function is not provably
        # publication-free.
        return True
    raw_tokens = shell_tokens(run)
    tokens = [executable_name(item).lower() for item in raw_tokens]
    for index in command_indexes(raw_tokens):
        name = tokens[index]
        arguments = [token.lower() for token in raw_command_arguments(raw_tokens, index)]
        if command_token_has_dynamic_executable(raw_tokens[index]) and (
            "push" in arguments[:3]
            or arguments[:1] in (["copy"], ["cp"], ["sync"], ["tag"], ["append"], ["mutate"])
        ):
            # `cmd=docker; "$cmd" push ...` cannot be proven publication-free.
            return True
        if name == "oras" and "push" in arguments[:2]:
            return True
        if name == "crane" and arguments[:1] in (
            ["push"], ["copy"], ["cp"], ["tag"], ["append"], ["mutate"], ["index"],
        ):
            return True
        if name == "skopeo" and arguments[:1] in (["copy"], ["sync"]):
            return True
        if name == "regctl" and any(
            token in {"push", "copy", "put", "set"} for token in arguments[:3]
        ):
            return True
        if name not in {"docker", "podman"}:
            continue
        if "push" in arguments[:4]:
            return True
        if arguments[:2] == ["buildx", "bake"]:
            # Bake targets can carry registry outputs in repository HCL; an
            # unparsed bake invocation cannot prove that it is build-only.
            return True
        if arguments[:3] == ["buildx", "imagetools", "create"]:
            return True
        if not (arguments[:2] == ["buildx", "build"] or arguments[:1] == ["build"]):
            continue
        for argument_index, argument in enumerate(arguments):
            if argument == "--push" or argument.startswith("--push=") and argument != "--push=false":
                return True
            output = ""
            if argument in {"--output", "-o"}:
                if argument_index + 1 >= len(arguments):
                    return True
                output = arguments[argument_index + 1]
            elif argument.startswith("--output="):
                output = argument.split("=", 1)[1]
            elif argument.startswith("-o") and len(argument) > 2:
                output = argument[2:]
            if output and (
                "$" in output
                or "`" in output
                or output == "SUBSTITUTION"
            ):
                # A computed exporter can resolve to type=registry (or an
                # image exporter with push=true), so it is a publication.
                return True
            fields = {
                key.strip(): value.strip()
                for field in output.split(",")
                if "=" in field
                for key, value in [field.split("=", 1)]
            }
            if fields.get("type") == "registry" or (
                fields.get("type") == "image" and fields.get("push") != "false"
            ):
                return True
    return False


def job_condition(job: WorkflowJob) -> str | None:
    value = job.data.get("if")
    return value if isinstance(value, str) else None


def condition_expression_parts(expression: str, operator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(expression):
        character = expression[index]
        if escaped:
            escaped = False
        elif character == "\\" and quote is not None:
            escaped = True
        elif quote is not None:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return [expression]
        elif depth == 0 and expression.startswith(operator, index):
            parts.append(expression[start:index].strip())
            start = index + len(operator)
            index += len(operator) - 1
        index += 1
    if quote is not None or depth != 0 or not parts:
        return [expression]
    parts.append(expression[start:].strip())
    return parts


def strip_condition_parentheses(expression: str) -> str:
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        quote: str | None = None
        closes_at_end = False
        for index, character in enumerate(expression):
            if quote is not None:
                if character == quote and (index == 0 or expression[index - 1] != "\\"):
                    quote = None
                continue
            if character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    closes_at_end = index == len(expression) - 1
                    break
        if not closes_at_end:
            break
        expression = expression[1:-1].strip()
    return expression


def condition_constant_value(expression: str) -> tuple[bool, object]:
    value = strip_condition_parentheses(expression.strip())
    if value == "true":
        return True, True
    if value == "false":
        return True, False
    if value == "null":
        return True, None
    if re.fullmatch(r"-?\d+", value):
        return True, int(value)
    if re.fullmatch(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"$""", value):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return False, None
        if isinstance(parsed, str):
            return True, parsed
    return False, None


def condition_is_statically_false(value: object) -> bool:
    if value is False or type(value) is int and value == 0:
        return True
    if not isinstance(value, str):
        return False
    expression = value.strip().lower()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    expression = strip_condition_parentheses(expression)
    disjunction = condition_expression_parts(expression, "||")
    if len(disjunction) > 1:
        return all(condition_is_statically_false(part) for part in disjunction)
    conjunction = condition_expression_parts(expression, "&&")
    if len(conjunction) > 1:
        return any(condition_is_statically_false(part) for part in conjunction)
    compact = re.sub(r"\s+", "", expression)
    if compact in {"false", "!true", "nottrue", "0", "null", "''", '""'}:
        return True
    comparison: tuple[str, str, str] | None = None
    for operator in ("!=", "=="):
        operands = condition_expression_parts(expression, operator)
        if len(operands) == 2:
            comparison = (operands[0], operator, operands[1])
            break
        if len(operands) > 2:
            return False
    if comparison is not None:
        left, operator, right = comparison
        left_is_constant, left_value = condition_constant_value(left)
        right_is_constant, right_value = condition_constant_value(right)
        if not (
            left_is_constant
            and right_is_constant
            and type(left_value) is type(right_value)
        ):
            return False
        equal = left_value == right_value
        return equal if operator == "!=" else not equal
    return False


def job_condition_is_statically_false(job: WorkflowJob) -> bool:
    return condition_is_statically_false(job.data.get("if"))


def job_executable_configuration_mutation(
    job: WorkflowJob,
    *,
    approved: bool = False,
) -> bool:
    """Treat unreviewed job containers and services as executable code."""

    return not approved and ("container" in job.data or "services" in job.data)


def job_executable_configuration_approved(workflow: str, path: str) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    return (
        APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256.get(repository, {}).get(path)
        == hashlib.sha256(workflow.encode()).hexdigest()
    )


def job_reusable_workflow_mutation(
    job: WorkflowJob,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    value = job.data.get("uses")
    if value is None:
        return False
    if not isinstance(value, str) or "${{" in value:
        return True
    normalized = value.split(" #", 1)[0].strip()
    if not normalized.startswith("./.github/workflows/"):
        return True
    candidate = ROOT / normalized.removeprefix("./")
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((ROOT / ".github/workflows").resolve())
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if seen_workflows is None:
        seen_workflows = set()
    if resolved in seen_workflows:
        return True
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    return workflow_has_runtime_mutation(
        resolved.read_text(encoding="utf-8"),
        relative,
        seen_workflows | {resolved},
    )


def workflow_script_aliases(workflow: str, path: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    pattern = re.compile(
        r'^\s*install\s+-m\s+0?755\s+([A-Za-z0-9_./-]+)\s+["\']?(\$\{?RUNNER_TEMP\}?/[A-Za-z0-9_.-]+)["\']?\s*$'
    )
    for job in workflow_jobs(workflow, path).values():
        for step in workflow_steps(job, path):
            uses = step.get("uses")
            inputs = step.get("with")
            if (
                isinstance(uses, str)
                and uses.startswith("actions/checkout@")
                and isinstance(inputs, dict)
                and isinstance(inputs.get("path"), str)
                and inputs.get("repository", repository) == repository
            ):
                checkout_path = str(inputs["path"]).strip("/")
                require(
                    bool(checkout_path)
                    and "${{" not in checkout_path
                    and "$" not in checkout_path,
                    f"checkout path is dynamic or invalid: {path}",
                )
                alias = f"{checkout_path}/"
                require(alias not in aliases, f"duplicate checkout path binding: {path}")
                aliases[alias] = ""
            script = str(step.get("run", "")).replace("\\\n", " ")
            for line in script.splitlines():
                match = pattern.fullmatch(line)
                if not match:
                    continue
                source, destination = match.groups()
                destination = destination.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
                require(destination not in aliases, f"duplicate generated script binding: {path}")
                candidate = step_working_directory(job, step, path) / source
                require(
                    candidate.is_file() and not candidate.is_symlink(),
                    f"generated script source is missing or unsafe: {path}",
                )
                aliases[destination] = source
    return aliases


def repository_script_has_runtime_contact(
    target: str,
    script_aliases: dict[str, str],
    working_directory: Path,
) -> bool:
    normalized_target = target.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
    if normalized_target in script_aliases:
        target = script_aliases[normalized_target]
    else:
        for prefix, replacement in script_aliases.items():
            if prefix.endswith("/") and normalized_target.startswith(prefix):
                target = replacement + normalized_target.removeprefix(prefix)
                break
    if "${{" in target or "$" in target:
        return True
    relative_target = target.removeprefix("./")
    if Path(relative_target).is_absolute() or any(
        marker in relative_target for marker in "*?["
    ):
        return True
    candidate = working_directory / relative_target
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return True
    if candidate.is_symlink() or not resolved.is_file():
        return True
    if resolved == RELEASE_VALIDATOR_PATH.resolve():
        validate_release_validator_operations(resolved.read_text(encoding="utf-8"))
        return False
    # A repository script can import an arbitrary local helper, so source-only
    # inspection of its entrypoint is insufficient to prove no runtime contact.
    # The release validator above is the sole dependency with a dedicated
    # operation contract.
    return True


def step_has_runtime_contact(
    job: WorkflowJob,
    step: dict[str, Any],
    path: str,
    script_aliases: dict[str, str],
) -> bool:
    run = str(step.get("run", ""))
    shell = step.get("shell", job.shell)
    shell_name = ""
    if shell is not None:
        if not isinstance(shell, str) or "${{" in shell or "$" in shell:
            return True
        shell_name = executable_name(shell.split()[0]).lower() if shell.split() else ""
        if shell_name in SCRIPT_INTERPRETERS:
            # The exact repository validator remains available as a normal
            # shell command and is checked through its dedicated operation
            # contract. Arbitrary declared script-language shells are unproved.
            return True
        if shell_name not in {"bash", "dash", "sh", "zsh"}:
            return True
    # This exact toolchain bootstrap does not address a governed runtime. Keep
    # the exception literal so added flags, packages, or compound commands
    # fall through to the conservative module/network classifier below.
    if run.strip() == PINNED_WORKFLOW_PARSER_INSTALL:
        return False
    if contains_runtime_command(run) or step_has_runtime_mutation(
        job,
        step,
        path,
        script_aliases,
    ):
        return True
    for interpreter, body in heredoc_programs(run):
        if interpreter in {"python", "python3"}:
            if python_source_has_runtime_contact(body):
                return True
        elif interpreter == "node":
            if javascript_source_has_runtime_contact(body):
                return True
        elif interpreter in SHELL_INTERPRETERS:
            if contains_runtime_command(body) or contains_runtime_mutation(body):
                return True
        else:
            return True
    tokens = shell_tokens(shell_without_heredoc_bodies(run))
    for index in command_indexes(tokens):
        interpreter = executable_name(tokens[index]).lower()
        if interpreter in GENERIC_NETWORK_CLIENTS:
            # Generic network clients cannot prove that a read-only-looking
            # request is not contacting the governed runtime.
            return True
        payload = interpreter_payload(tokens, index)
        if payload is not None:
            if inline_interpreter_payload_has_runtime_contact(interpreter, payload):
                return True
        target = interpreter_script_target(tokens, index)
        if target is not None and repository_script_has_runtime_contact(
            target,
            script_aliases,
            step_working_directory(job, step, path),
        ):
            return True
        module_target = interpreter_module_target(
            tokens,
            index,
            step_working_directory(job, step, path),
        )
        if module_target is not None:
            return True
        direct_target = direct_repository_script_target(
            tokens,
            index,
            step_working_directory(job, step, path),
        )
        if direct_target is not None and repository_script_has_runtime_contact(
            direct_target,
            script_aliases,
            step_working_directory(job, step, path),
        ):
            return True
    return False


def workflow_has_runtime_command(workflow: str, path: str) -> bool:
    jobs = workflow_jobs(workflow, path)
    script_aliases = workflow_script_aliases(workflow, path)
    return any(
        # Release-intent evidence promises that no runtime was contacted, so
        # declared Python/Node shells, inline programs, and invoked repository
        # scripts require the stronger contact-aware classifier.
        step_has_runtime_contact(job, step, path, script_aliases)
        for job in jobs.values()
        for step in workflow_steps(job, path)
    )


def step_has_runtime_mutation(
    job: WorkflowJob,
    step: dict[str, Any],
    path: str,
    script_aliases: dict[str, str],
) -> bool:
    run = str(step.get("run", ""))
    environment = step_environment(job, step)
    if environment is None or environment_has_unproved_executable_startup(
        environment
    ):
        # Workflow, job, and step environment mappings can preload code or
        # redirect executable/module resolution before the literal run block.
        return True
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_offline = hashlib.sha256(
        run.encode()
    ).hexdigest() in APPROVED_OFFLINE_RUN_SHA256.get(repository, {}).get(
        path,
        frozenset(),
    )
    if approved_offline:
        # The exception binds the complete execution envelope, not only the
        # run bytes. Environment or shell changes can turn the same fixture
        # into an executable preload or redirect its fake tools.
        # Exact-hash offline run blocks may use GitHub's default bash shell
        # or declare `shell: bash` explicitly. No environment, working-directory,
        # or extra step keys are admitted because those can redirect execution.
        allowed_step_keys = {"name", "run"}
        if "shell" in step:
            allowed_step_keys.add("shell")
        allowed_job_environment: dict[str, object] = {}
        if repository == "ingtrader21-spec/Middleware-" and path in {
            ".github/workflows/trusted-production-orchestrator-gate.yml",
            ".github/workflows/production-orchestrator-contract.yml",
        }:
            if path == ".github/workflows/trusted-production-orchestrator-gate.yml":
                allowed_job_environment = {
                    "EXPECTED_SHA": "${{ github.event.pull_request.head.sha }}",
                    "COMPARISON_SHA": "${{ github.event.pull_request.base.sha }}",
                    "GITHUB_REPOSITORY_ID": "${{ github.repository_id }}",
                    "VALIDATION_ROOT": "${{ github.workspace }}/candidate",
                }
            else:
                allowed_job_environment = {
                    "EXPECTED_SHA": "${{ (github.event_name == 'pull_request_target' || github.event_name == 'pull_request') && github.event.pull_request.head.sha || github.sha }}",
                    "COMPARISON_SHA": "${{ (github.event_name == 'pull_request_target' || github.event_name == 'pull_request') && github.event.pull_request.base.sha || github.event.before }}",
                    "GITHUB_REPOSITORY_ID": "${{ github.repository_id }}",
                    "VALIDATION_ROOT": "${{ github.workspace }}/candidate",
                }
        if (
            set(step) != allowed_step_keys
            or step.get("shell") not in {None, "bash"}
            or job.shell is not None
            or job.working_directory is not None
            or job.environment != allowed_job_environment
        ):
            return True
        return False
    shell = step.get("shell", job.shell)
    if shell is not None:
        if not isinstance(shell, str) or "${{" in shell or "$" in shell:
            return True
        shell_name = executable_name(shell.split()[0]).lower() if shell.split() else ""
        if shell_name in {"python", "python3"}:
            return python_source_has_runtime_mutation(run)
        if shell_name == "node":
            return javascript_source_has_runtime_mutation(run)
        if shell_name not in {"bash", "dash", "sh", "zsh"}:
            # PowerShell, cmd, and custom shells are not parsed by the POSIX
            # classifier. An unproved run block must be treated as mutating.
            return True
    return contains_runtime_mutation(
        run,
        script_aliases=script_aliases,
        working_directory=step_working_directory(job, step, path),
    )


def verified_control_plane_dependencies(
    repository: str,
    workflow_path: str,
) -> frozenset[str] | None:
    manifest = APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256.get(repository, {}).get(
        workflow_path,
        {},
    )
    trusted_scripts: set[str] = set()
    for relative, expected_hash in manifest.items():
        candidate = ROOT / relative
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(ROOT.resolve())
        except (OSError, ValueError):
            return None
        if candidate.is_symlink() or not resolved.is_file():
            return None
        if hashlib.sha256(resolved.read_bytes()).hexdigest() != expected_hash:
            return None
        if resolved.suffix.lower() in SCRIPT_SUFFIXES:
            trusted_scripts.add(relative)
    return frozenset(trusted_scripts)


def workflow_has_runtime_mutation(
    workflow: str,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_hash = APPROVED_CONTROL_PLANE_WORKFLOW_SHA256.get(repository, {}).get(
        path
    )
    if approved_hash is not None:
        if hashlib.sha256(workflow.encode()).hexdigest() != approved_hash:
            return True
        trusted_scripts = verified_control_plane_dependencies(repository, path)
        if trusted_scripts is None:
            return True
        if path in {
            ".github/workflows/portfolio-main-release-authorities.yml",
            ".github/workflows/portfolio-production-ruleset-apply.yml",
        }:
            # This exact, dependency-bound workflow mutates repository
            # governance only behind its explicit manual confirmation. It has
            # no application-runtime authority and is not a production
            # deployment path.
            return False
        script_aliases = workflow_script_aliases(workflow, path)
        return any(
            job_reusable_workflow_mutation(job, path, seen_workflows)
            or any(
                script_dependencies_have_runtime_mutation(
                    str(step.get("run", "")),
                    script_aliases,
                    step_working_directory(job, step, path),
                    trusted_scripts,
                )
                or isinstance(step.get("uses"), str)
                and str(step["uses"]).strip().startswith("./")
                for step in workflow_steps(job, path)
            )
            for job in workflow_jobs(workflow, path).values()
        )
    if seen_workflows is None:
        seen_workflows = set()
    script_aliases = workflow_script_aliases(workflow, path)
    approved_job_configuration = job_executable_configuration_approved(
        workflow,
        path,
    )
    return any(
        job_executable_configuration_mutation(
            job,
            approved=approved_job_configuration,
        )
        or job_reusable_workflow_mutation(job, path, seen_workflows)
        or any(
            step_has_runtime_mutation(job, step, path, script_aliases)
            or contains_runtime_action(step)
            for step in workflow_steps(job, path)
        )
        for job in workflow_jobs(workflow, path).values()
    )


def workflow_has_image_publication(workflow: str, path: str) -> bool:
    return any(
        contains_image_publication(step)
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def workflow_actions(workflow: str, path: str) -> list[str]:
    jobs = workflow_jobs(workflow, path)
    actions = [
        str(step["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        for step in workflow_steps(job, path)
        if isinstance(step.get("uses"), str) and step["uses"]
    ]
    actions.extend(
        str(job.data["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        if isinstance(job.data.get("uses"), str) and job.data["uses"]
    )
    return actions


def require_immutable_action_references(workflow: str, path: str) -> None:
    for reference in workflow_actions(workflow, path):
        if reference.startswith("./"):
            continue
        if reference.startswith("docker://"):
            require(
                re.fullmatch(
                    r"docker://[^\s@]+@sha256:[0-9a-f]{64}",
                    reference,
                )
                is not None,
                f"workflow uses a mutable container action: {path}:{reference}",
            )
            continue
        require(
            re.fullmatch(r"[^\s@]+@[0-9a-f]{40}", reference) is not None,
            f"workflow uses a mutable external action: {path}:{reference}",
        )


def step_has_reachable_attestation(step: dict[str, Any]) -> bool:
    if condition_is_statically_false(step.get("if")):
        return False
    if step.get("continue-on-error", False) is not False:
        return False
    uses = step.get("uses")
    if isinstance(uses, str) and uses.startswith(
        ("actions/attest@", "actions/attest-build-provenance@")
    ):
        return True
    run = str(step.get("run", ""))
    shell = step.get("shell")
    if shell is not None and (
        not isinstance(shell, str)
        or re.match(r"^(?:bash|sh)(?:\s|$)", shell) is None
    ):
        return False
    shell_source = shell_without_heredoc_bodies(run)
    raw_tokens = shell_tokens(shell_source)
    ambiguous_control = {
        "(",
        ")",
        "&&",
        "||",
        "case",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "function",
        "if",
        "select",
        "then",
        "until",
        "while",
        "{",
        "}",
    }
    if any(token.lower() in ambiguous_control for token in raw_tokens):
        # A syntactic cosign command inside shell control flow is not proof
        # that an attestation is executable on a successful publication path.
        return False
    for command_index in command_indexes(raw_tokens):
        if executable_name(raw_tokens[command_index]).lower() in {
            "break",
            "continue",
            "exit",
            "return",
        }:
            return False
    for index in command_indexes(raw_tokens):
        if executable_name(raw_tokens[index]).lower() != "cosign":
            continue
        arguments = raw_command_arguments(raw_tokens, index)
        if arguments and arguments[0].lower() == "attest":
            return True
    return False


def attestation_covers_publication(
    attestation: dict[str, Any],
    publication: dict[str, Any],
) -> bool:
    if attestation.get("continue-on-error", False) is not False:
        return False

    def condition(step: dict[str, Any]) -> str:
        value = step.get("if")
        if value is None or value is True:
            return "success()"
        if not isinstance(value, str):
            return "__unproved__"
        expression = value.strip()
        if expression.startswith("${{") and expression.endswith("}}"):
            expression = expression[3:-2].strip()
        return strip_condition_parentheses(expression)

    attestation_condition = condition(attestation)
    return attestation_condition in {"success()", "true", "always()"} or (
        attestation_condition != "__unproved__"
        and attestation_condition == condition(publication)
    )


def normalized_image_subject(
    value: object,
    environment: dict[str, object] | None = None,
    *,
    resolving: frozenset[str] = frozenset(),
) -> str | None:
    if not isinstance(value, str):
        return None
    subject = value.strip()
    if (
        len(subject) >= 2
        and subject[0] == subject[-1]
        and subject[0] in {"'", '"'}
    ):
        subject = subject[1:-1].strip()
    if not subject or any(character in subject for character in "`\r\n\0"):
        return None
    variable = re.fullmatch(
        r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
        subject,
    )
    if variable is not None:
        name = variable.group(1) or variable.group(2)
        if environment is None or name in resolving or name not in environment:
            return None
        return normalized_image_subject(
            environment[name],
            environment,
            resolving=resolving | {name},
        )
    if "$" in subject:
        return None
    return subject


def literal_image_repository(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or any(character in candidate for character in "`\r\n\0"):
        return None
    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]
    elif candidate.rfind(":") > candidate.rfind("/"):
        candidate = candidate.rsplit(":", 1)[0]
    if "$" in candidate:
        return None
    if re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", candidate) is None:
        return None
    return candidate


def bound_image_repository(value: object) -> str | None:
    """Return a literal or same-expression-bound image repository.

    Matrix, environment, and preceding-step outputs are admitted only as
    complete GitHub expression atoms. Publication and attestation must resolve
    to the same normalized symbolic repository, so dynamic values cannot
    detach the attestation from the image that was pushed.
    """

    literal = literal_image_repository(value)
    if literal is not None:
        return literal
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]
    elif candidate.rfind(":") > candidate.rfind("/"):
        candidate = candidate.rsplit(":", 1)[0]
    if not candidate or any(character in candidate for character in "`\r\n\0"):
        return None
    expression = re.compile(
        r"\$\{\{\s*(?:env\.[A-Z_][A-Z0-9_]*|matrix\.[A-Za-z_][A-Za-z0-9_]*|"
        r"steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
    )
    position = 0
    normalized: list[str] = []
    for match in expression.finditer(candidate):
        literal_part = candidate[position : match.start()]
        if re.fullmatch(r"[A-Za-z0-9._/-]*", literal_part) is None:
            return None
        normalized.append(literal_part)
        normalized.append(re.sub(r"\s+", "", match.group(0)))
        position = match.end()
    suffix = candidate[position:]
    if not normalized or re.fullmatch(r"[A-Za-z0-9._/-]*", suffix) is None:
        return None
    normalized.append(suffix)
    result = "".join(normalized)
    complete_step_output = re.fullmatch(
        r"\$\{\{steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\."
        r"[A-Za-z_][A-Za-z0-9_-]*\}\}",
        result,
    )
    if (
        "/" not in result
        and complete_step_output is None
        or result.startswith(("/", "."))
        or "//" in result
    ):
        return None
    return result


def step_environment(
    job: WorkflowJob,
    step: dict[str, Any],
) -> dict[str, object] | None:
    environment: dict[str, object] = {}
    for source in (job.environment, step.get("env", {})):
        if not isinstance(source, dict) or not all(
            isinstance(name, str) and bool(name)
            for name in source
        ):
            return None
        environment.update(source)
    return environment


def environment_has_unproved_executable_startup(
    environment: dict[str, object],
) -> bool:
    """Reject YAML environment hooks except source-bound Python import roots."""

    for name, value in environment.items():
        upper = name.upper()
        if upper not in EXECUTABLE_STARTUP_ENV:
            continue
        if upper != "PYTHONPATH" or not isinstance(value, str) or not value:
            return True
        for component in value.split(":"):
            normalized = re.sub(
                r"^\$\{\{\s*github\.workspace\s*\}\}(?:/|$)",
                "",
                component,
            )
            if (
                component.startswith("/")
                and normalized == component
                or "$" in normalized
                or not normalized
                and component != "${{ github.workspace }}"
                or any(part == ".." for part in Path(normalized or ".").parts)
                or re.fullmatch(r"[A-Za-z0-9_./-]*", normalized) is None
            ):
                return True
    return False


def publication_subjects(
    step: dict[str, Any],
    environment: dict[str, object] | None = None,
) -> set[str]:
    subjects: set[str] = set()
    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and isinstance(inputs, dict):
        normalized = uses.split(" #", 1)[0].strip().lower()
        if normalized.startswith("docker/build-push-action@"):
            tags = inputs.get("tags")
            step_id = step.get("id")
            if not isinstance(tags, str) or not isinstance(step_id, str) or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_-]*",
                step_id,
            ) is None:
                return set()
            for raw_tag in re.split(r"[\r\n,]+", tags):
                if not raw_tag.strip():
                    continue
                repository = bound_image_repository(raw_tag)
                if repository is None:
                    return set()
                subjects.add(
                    f"{repository}@${{{{ steps.{step_id}.outputs.digest }}}}"
                )
        elif normalized.startswith("actions/attest-build-provenance@"):
            repository = bound_image_repository(inputs.get("subject-name"))
            digest = inputs.get("subject-digest")
            if repository is not None and isinstance(digest, str):
                subjects.add(f"{repository}@{digest.strip()}")

    raw_tokens = shell_tokens(str(step.get("run", "")))
    for index in command_indexes(raw_tokens):
        if executable_name(raw_tokens[index]).lower() not in {"docker", "podman"}:
            continue
        arguments = raw_command_arguments(raw_tokens, index)
        lowered = [argument.lower() for argument in arguments]
        if "push" in lowered[:4]:
            push_index = lowered.index("push")
            candidates = [
                argument
                for argument in arguments[push_index + 1 :]
                if not argument.startswith("-")
            ]
            if candidates:
                subject = normalized_image_subject(candidates[-1], environment)
                if subject is not None and re.fullmatch(
                    r"[^@\s]+@sha256:[0-9a-f]{64}",
                    subject,
                ) is not None:
                    subjects.add(subject)
        for argument_index, argument in enumerate(arguments):
            if argument in {"--tag", "-t"} and argument_index + 1 < len(arguments):
                subject = normalized_image_subject(
                    arguments[argument_index + 1], environment
                )
            elif argument.startswith("--tag="):
                subject = normalized_image_subject(
                    argument.split("=", 1)[1], environment
                )
            elif argument.startswith("-t") and len(argument) > 2:
                subject = normalized_image_subject(argument[2:], environment)
            else:
                continue
            if subject is not None:
                subjects.add(subject)
    return subjects


def attestation_subjects(
    step: dict[str, Any],
    environment: dict[str, object] | None = None,
) -> set[str]:
    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and uses.startswith(
        ("actions/attest@", "actions/attest-build-provenance@")
    ):
        if not isinstance(inputs, dict):
            return set()
        repository = bound_image_repository(inputs.get("subject-name"))
        digest = inputs.get("subject-digest")
        if (
            repository is None
            or not isinstance(digest, str)
            or re.fullmatch(
                r"\$\{\{\s*steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.digest\s*\}\}",
                digest.strip(),
            )
            is None
        ):
            return set()
        subject = f"{repository}@{digest.strip()}"
        return {subject}

    raw_tokens = shell_tokens(str(step.get("run", "")))
    subjects: set[str] = set()
    for index in command_indexes(raw_tokens):
        if executable_name(raw_tokens[index]).lower() != "cosign":
            continue
        arguments = raw_command_arguments(raw_tokens, index)
        if not arguments or arguments[0].lower() != "attest":
            continue
        candidates = [argument for argument in arguments[1:] if not argument.startswith("-")]
        if not candidates:
            return set()
        raw_subject = candidates[-1].strip()
        if (
            len(raw_subject) >= 2
            and raw_subject[0] == raw_subject[-1]
            and raw_subject[0] in {"'", '"'}
        ):
            raw_subject = raw_subject[1:-1].strip()
        resolved_subject = normalized_image_subject(raw_subject, environment)
        if resolved_subject is not None and re.fullmatch(
            r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}",
            resolved_subject,
        ) is not None:
            subjects.add(resolved_subject)
            continue
        if re.fullmatch(
            r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+@(?:sha256:[0-9a-f]{64}|"
            r"\$\{\{\s*steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.digest\s*\}\})",
            raw_subject,
        ) is None:
            return set()
        subjects.add(raw_subject)
    return subjects


def attestation_targets_publication(
    attestation: dict[str, Any],
    publication: dict[str, Any],
    *,
    attestation_environment: dict[str, object] | None = None,
    publication_environment: dict[str, object] | None = None,
) -> bool:
    published = publication_subjects(publication, publication_environment)
    attested = attestation_subjects(attestation, attestation_environment)
    if not published or not attested or published.isdisjoint(attested):
        return False
    return True


def require_reachable_signer_workflow(workflow: str, path: str) -> None:
    jobs = workflow_jobs(workflow, path)

    def job_is_statically_blocked(
        job_id: str,
        seen: frozenset[str] = frozenset(),
    ) -> bool:
        if job_id in seen or job_id not in jobs:
            return True
        job = jobs[job_id]
        if job_condition_is_statically_false(job):
            return True
        needs = job.data.get("needs", [])
        if isinstance(needs, str):
            dependencies = [needs]
        elif isinstance(needs, list) and all(
            isinstance(item, str) and item for item in needs
        ):
            dependencies = needs
        elif needs in (None, []):
            dependencies = []
        else:
            return True
        return any(
            job_is_statically_blocked(dependency, seen | {job_id})
            for dependency in dependencies
        )

    publication_jobs = [
        (job_id, job)
        for job_id, job in jobs.items()
        if not job_is_statically_blocked(job_id)
        if any(
            not condition_is_statically_false(step.get("if"))
            and contains_image_publication(step)
            and not step_has_reachable_attestation(step)
            for step in workflow_steps(job, path)
        )
    ]
    require(bool(publication_jobs), f"signer workflow has no image publication job: {path}")
    require(
        any(
            not job_condition_is_statically_false(job)
            for _, job in publication_jobs
        ),
        f"signer workflow image publication is unreachable: {path}",
    )
    for _, publication_job in publication_jobs:
        steps = workflow_steps(publication_job, path)
        publications = [
            (index, step, step_environment(publication_job, step))
            for index, step in enumerate(steps)
            if not condition_is_statically_false(step.get("if"))
            and contains_image_publication(step)
            and not step_has_reachable_attestation(step)
        ]
        for publication_index, publication, publication_environment in publications:
            published = publication_subjects(publication, publication_environment)
            covered: set[str] = set()
            for attestation in steps[publication_index + 1 :]:
                attestation_environment = step_environment(
                    publication_job, attestation
                )
                if (
                    step_has_reachable_attestation(attestation)
                    and attestation_covers_publication(attestation, publication)
                    and attestation_targets_publication(
                        attestation,
                        publication,
                        attestation_environment=attestation_environment,
                        publication_environment=publication_environment,
                    )
                ):
                    covered.update(
                        attestation_subjects(attestation, attestation_environment)
                    )
            require(
                bool(published) and published <= covered,
                f"signer publication subjects lack guaranteed attestations: {path}",
            )
        for attestation_index, attestation in enumerate(steps):
            if not step_has_reachable_attestation(attestation):
                continue
            attestation_environment = step_environment(publication_job, attestation)
            attested = attestation_subjects(attestation, attestation_environment)
            eligible_publications: set[str] = set()
            for publication_index, publication, publication_environment in publications:
                if (
                    publication_index < attestation_index
                    and attestation_covers_publication(attestation, publication)
                    and attestation_targets_publication(
                        attestation,
                        publication,
                        attestation_environment=attestation_environment,
                        publication_environment=publication_environment,
                    )
                ):
                    eligible_publications.update(
                        publication_subjects(publication, publication_environment)
                    )
            require(
                bool(attested) and attested <= eligible_publications,
                f"signer attestation is not bound to a preceding publication: {path}",
            )


def validate_intent_source_binding(intent: str) -> None:
    require_immutable_action_references(
        intent,
        ".github/workflows/manual-release-intent.yml",
    )
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("verify" in jobs, "release-intent verify job is missing")
    steps = workflow_steps(jobs["verify"], ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@")
    ]
    require(len(checkout_indexes) == 1, "release-intent must have one exact checkout step")
    checkout_index = checkout_indexes[0]
    checkout = steps[checkout_index]
    require(
        checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "release-intent checkout action is not pinned",
    )
    require(
        checkout["with"].get("ref") == "${{ github.sha }}",
        "release-intent checkout is not bound to the workflow commit",
    )
    require(
        checkout["with"].get("persist-credentials") is False,
        "release-intent checkout persists credentials",
    )
    precheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("name")
        == "Verify dispatched source is current protected head before checkout"
    ]
    require(len(precheck_indexes) == 1, "release-intent protected-head precheck is missing")
    require(precheck_indexes[0] < checkout_index, "release-intent checks out before validating the protected head")
    precheck = steps[precheck_indexes[0]]
    require(
        precheck["env"].get("GH_TOKEN") == "${{ github.token }}"
        and precheck["env"].get("EVENT_SHA") == "${{ github.sha }}"
        and precheck["env"].get("REQUESTED_SOURCE_SHA") == "${{ inputs.source_sha }}",
        "release-intent protected-head precheck environment is not exact",
    )
    commands = {
        line.strip()
        for line in str(precheck.get("run", "")).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required_commands = {
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
        'branch="$(gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)"',
        'test "$branch" = "main"',
        'head="$(gh api "repos/${GITHUB_REPOSITORY}/branches/${branch}" --jq .commit.sha)"',
        'test "$head" = "$EVENT_SHA"',
    }
    require(
        required_commands <= commands,
        "release-intent protected-head precheck is incomplete",
    )


def validate_protected_job_recheck(intent: str) -> None:
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("protected-intent" in jobs, "release-intent protected job is missing")
    job = jobs["protected-intent"]
    require(
        job.data.get("environment")
        == {"name": "${{ needs.verify.outputs.environment }}"},
        "protected job environment binding is not exact",
    )
    steps = workflow_steps(job, ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("uses")
        == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        and step.get("with", {}).get("ref") == "${{ github.sha }}"
        and step.get("with", {}).get("persist-credentials") is False
    ]
    recheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("run")
        == "python3 .codestra/validate-release-intent.py --recheck-protected-gates"
    ]
    require(len(checkout_indexes) == 1, "protected job exact checkout is missing")
    require(len(recheck_indexes) == 1, "protected job policy recheck is missing")
    require(checkout_indexes[0] < recheck_indexes[0], "protected job rechecks before exact checkout")
    recheck = steps[recheck_indexes[0]]
    expected_env = {
        "GH_TOKEN": "${{ github.token }}",
        "CODESTRA_ORCHESTRATOR_TOKEN": "${{ secrets.CODESTRA_ORCHESTRATOR_TOKEN }}",
        "PHASE": "${{ inputs.phase }}",
        "SOURCE_SHA": "${{ inputs.source_sha }}",
        "RELEASE_ID": "${{ inputs.release_id }}",
        "CANDIDATE_SHA256": "${{ inputs.candidate_sha256 }}",
        "IMAGES_JSON": "${{ inputs.images_json }}",
        "PREVIOUS_IMAGES_JSON": "${{ inputs.previous_images_json }}",
        "PRIOR_EVIDENCE_SHA256": "${{ inputs.prior_evidence_sha256 }}",
        "PRIOR_EVIDENCE_RUN_ID": "${{ inputs.prior_evidence_run_id }}",
        "PREAPPROVAL_EVIDENCE_B64": "${{ needs.verify.outputs.evidence_b64 }}",
    }
    require(recheck.get("env") == expected_env, "protected job policy recheck inputs are incomplete")


def validate_release_validator_gate_rechecks(source: str) -> None:
    """Require reachable, ordered exact-gate checks on every successful path."""

    try:
        tree = ast.parse(source, filename=str(RELEASE_VALIDATOR_PATH))
    except SyntaxError as exc:
        raise ContractError("release-intent validator is not valid Python") from exc
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    def statement_named_call(statement: ast.stmt) -> tuple[str, str | None] | None:
        value: ast.expr | None = None
        target: str | None = None
        if isinstance(statement, ast.Expr):
            value = statement.value
        elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            value = statement.value
            if isinstance(statement.targets[0], ast.Name):
                target = statement.targets[0].id
        elif isinstance(statement, ast.AnnAssign):
            value = statement.value
            if isinstance(statement.target, ast.Name):
                target = statement.target.id
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
        ):
            return value.func.id, target
        return None

    def require_compares_heads(statement: ast.stmt, observed: str) -> bool:
        call = statement.value if isinstance(statement, ast.Expr) else None
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "require"
            and call.args
            and isinstance(call.args[0], ast.Compare)
        ):
            return False
        comparison = call.args[0]
        if len(comparison.ops) != 1 or not isinstance(comparison.ops[0], ast.Eq):
            return False
        names = {
            item.id
            for item in [comparison.left, *comparison.comparators]
            if isinstance(item, ast.Name)
        }
        return names == {observed, "controller_candidate_head"}

    for function_name in ("main", "recheck_protected_gates"):
        function = functions.get(function_name)
        if function is None:
            raise ContractError(f"release-intent {function_name} function is missing")
        returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
        require(
            len(returns) == 1
            and bool(function.body)
            and function.body[-1] is returns[0],
            f"release-intent {function_name} has an early or hidden success return",
        )
        named_calls = [
            (node, node.func.id)
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        top_level_calls = [
            (index, call)
            for index, statement in enumerate(function.body)
            if (call := statement_named_call(statement)) is not None
        ]
        gate_indexes = [
            index for index, (name, _) in top_level_calls
            if name == "validate_repository_gates"
        ]
        require(
            len(gate_indexes) >= 3,
            f"release-intent {function_name} lacks post-controller exact-head revalidation",
        )
        controller_indexes = [
            index for index, (name, _) in top_level_calls
            if name == "download_and_validate_candidate"
        ]
        require(
            len(controller_indexes) >= 3,
            f"release-intent {function_name} lacks controller stability revalidation",
        )
        sandwiched_gate = gate_indexes[-2]
        final_gate = gate_indexes[-1]
        before_gate_controller = controller_indexes[-2]
        after_gate_controller = controller_indexes[-1]
        require(
            before_gate_controller
            < sandwiched_gate
            < after_gate_controller
            and after_gate_controller + 1 < final_gate,
            f"release-intent {function_name} does not recheck source after its final controller observation",
        )
        before_call = statement_named_call(function.body[before_gate_controller])
        after_call = statement_named_call(function.body[after_gate_controller])
        require(
            before_call == (
                "download_and_validate_candidate",
                "final_controller_candidate_head",
            )
            and after_call == (
                "download_and_validate_candidate",
                "post_gate_controller_candidate_head",
            ),
            f"release-intent {function_name} controller rechecks are not bound to named observations",
        )
        require(
            before_gate_controller + 1 < len(function.body)
            and require_compares_heads(
                function.body[before_gate_controller + 1],
                "final_controller_candidate_head",
            )
            and after_gate_controller + 1 < len(function.body)
            and require_compares_heads(
                function.body[after_gate_controller + 1],
                "post_gate_controller_candidate_head",
            ),
            f"release-intent {function_name} does not compare reachable controller observations",
        )
        non_controller_slow_lines = [
            node.lineno
            for node, name in named_calls
            if name in {"download_prior_evidence", "validate_prior", "verify_supply_chain"}
        ]
        require(
            bool(non_controller_slow_lines)
            and function.body[before_gate_controller].lineno
            > max(non_controller_slow_lines),
            f"release-intent {function_name} revalidates gates before evidence verification finishes",
        )
        require(
            any(name == "download_prior_evidence" for _, name in named_calls)
            and any(name == "validate_prior" for _, name in named_calls),
            f"release-intent {function_name} omits prior-phase evidence revalidation",
        )


def validate_release_validator_operations(source: str) -> None:
    """Allow evidence clients only; reject runtime-capable execution paths."""

    try:
        tree = ast.parse(source, filename=str(RELEASE_VALIDATOR_PATH))
    except SyntaxError as exc:
        raise ContractError("release-intent validator is not valid Python") from exc

    def unresolved_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = unresolved_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    imports: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                imports.add(root)
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualified_name(node: ast.expr) -> str:
        raw = unresolved_name(node)
        root, separator, tail = raw.partition(".")
        replacement = aliases.get(root, root)
        return f"{replacement}.{tail}" if separator else replacement

    def is_os_process_launcher(name: str) -> bool:
        return (
            name.startswith("os.exec")
            or name.startswith("os.spawn")
            or name
            in {
                "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell",
                "os.posix_spawn",
                "os.posix_spawnp",
            }
        )

    prohibited_url_calls = {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.request.URLopener.open",
        "urllib.request.FancyURLopener.open",
    }
    command_bindings: dict[tuple[int, str], set[tuple[str, ...]]] = {}
    opener_bindings: set[str] = set()
    restricted_callable_roots = {
        "posix.popen",
        "posix.posix_spawn",
        "posix.posix_spawnp",
        "posix.spawn",
        "posix.spawnp",
        "posix.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.run",
    }

    def restricted_callable_name(name: str) -> bool:
        return (
            any(
                name == root or name.startswith(f"{root}.")
                for root in restricted_callable_roots
            )
            or is_os_process_launcher(name)
            or name in {"os.popen", "os.system"}
            or name.startswith(("os.popen.", "os.system."))
            or name in prohibited_url_calls
            or name == "urllib.request.Request"
        )

    def restricted_module_name(name: str) -> bool:
        return name in {
            "asyncio",
            "ftplib",
            "os",
            "posix",
            "pymongo",
            "subprocess",
            "urllib.request",
        }

    def expression_has_restricted_callable(value: ast.expr) -> bool:
        invoked = {
            id(child.func)
            for child in ast.walk(value)
            if isinstance(child, ast.Call)
        }
        attribute_receivers = {
            id(child.value)
            for child in ast.walk(value)
            if isinstance(child, ast.Attribute)
        }
        return any(
            id(child) not in invoked | attribute_receivers
            and isinstance(child, (ast.Name, ast.Attribute))
            and (
                restricted_callable_name(qualified_name(child))
                or restricted_module_name(qualified_name(child))
            )
            for child in ast.walk(value)
        )

    def target_value_pairs(
        target: ast.expr,
        value: ast.expr,
    ) -> list[tuple[str, ast.expr]]:
        if isinstance(target, ast.Name):
            return [(target.id, value)]
        if (
            isinstance(target, (ast.List, ast.Tuple))
            and isinstance(value, (ast.List, ast.Tuple))
            and len(target.elts) == len(value.elts)
        ):
            return [
                pair
                for child_target, child_value in zip(target.elts, value.elts)
                for pair in target_value_pairs(child_target, child_value)
            ]
        return []

    def named_assignments(node: ast.AST) -> list[tuple[str, ast.expr]]:
        if isinstance(node, ast.Assign):
            return [
                pair
                for target in node.targets
                for pair in target_value_pairs(target, node.value)
            ]
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            return [(node.target.id, node.value)]
        return []

    lexical_scopes: list[ast.AST] = [tree]
    lexical_scopes.extend(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    )

    def lexical_scope_id(node: ast.AST) -> int:
        line = getattr(node, "lineno", 0)
        containing = [
            scope
            for scope in lexical_scopes[1:]
            if getattr(scope, "lineno", 0) <= line
            <= getattr(scope, "end_lineno", -1)
        ]
        if not containing:
            return id(tree)
        return id(
            min(
                containing,
                key=lambda scope: (
                    getattr(scope, "end_lineno", 0) - getattr(scope, "lineno", 0),
                    -getattr(scope, "lineno", 0),
                ),
            )
        )

    scoped_assignment_values: dict[tuple[int, str], list[ast.expr]] = {}
    for candidate in ast.walk(tree):
        for target_name, value in named_assignments(candidate):
            scoped_assignment_values.setdefault(
                (lexical_scope_id(candidate), target_name),
                [],
            ).append(value)

    for node in ast.walk(tree):
        assigned_value: ast.expr | None = None
        assigned_targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            assigned_value = node.value
            assigned_targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assigned_value = node.value
            assigned_targets = [node.target]
        if assigned_value is not None:
            require(
                not (
                    any(
                        isinstance(target, (ast.Attribute, ast.Subscript))
                        for target in assigned_targets
                    )
                    and expression_has_restricted_callable(assigned_value)
                ),
                "release-intent validator stores a restricted callable on an unresolved target",
            )
        for target_name, value in named_assignments(node):
            if not isinstance(value, (ast.Name, ast.Attribute)):
                invoked_callables = {
                    id(child.func)
                    for child in ast.walk(value)
                    if isinstance(child, ast.Call)
                }
                embedded_restricted = any(
                    id(child) not in invoked_callables
                    and isinstance(child, (ast.Name, ast.Attribute))
                    and restricted_callable_name(qualified_name(child))
                    for child in ast.walk(value)
                )
                require(
                    not embedded_restricted,
                    "release-intent validator stores a restricted callable "
                    f"in an unresolved expression at line {value.lineno}: "
                    f"{target_name}",
                )
            if isinstance(value, (ast.Name, ast.Attribute)):
                callable_name = qualified_name(value)
                if restricted_callable_name(callable_name) or restricted_module_name(
                    callable_name
                ):
                    aliases[target_name] = callable_name
            if (
                isinstance(value, (ast.List, ast.Tuple))
                and all(
                    isinstance(assigned, (ast.List, ast.Tuple))
                    for assigned in scoped_assignment_values[
                        (lexical_scope_id(node), target_name)
                    ]
                )
            ):
                prefix: list[str] = []
                for item in value.elts:
                    if not isinstance(item, ast.Constant) or not isinstance(
                        item.value, str
                    ):
                        break
                    prefix.append(item.value)
                if prefix:
                    prefix[0] = executable_name(prefix[0])
                    command_bindings.setdefault(
                        (lexical_scope_id(node), target_name),
                        set(),
                    ).add(tuple(prefix))
            elif (
                isinstance(value, ast.Call)
                and qualified_name(value.func) == "urllib.request.build_opener"
            ):
                opener_bindings.add(target_name)
    require(
        imports <= ALLOWED_RELEASE_VALIDATOR_IMPORTS,
        "release-intent validator imports an unapproved module: "
        f"{sorted(imports - ALLOWED_RELEASE_VALIDATOR_IMPORTS)}",
    )

    allowed_subprocess_calls = {"check_output", "run"}

    def bound_commands(argument: ast.expr) -> set[tuple[str, ...]]:
        if isinstance(argument, (ast.List, ast.Tuple)):
            prefix: list[str] = []
            for item in argument.elts:
                if isinstance(item, ast.Starred) and isinstance(item.value, ast.Name):
                    if not prefix:
                        return command_bindings.get(
                            (lexical_scope_id(argument), item.value.id),
                            set(),
                        )
                    break
                if not isinstance(item, ast.Constant) or not isinstance(
                    item.value, str
                ):
                    break
                prefix.append(item.value)
            if prefix:
                prefix[0] = executable_name(prefix[0])
                return {tuple(prefix)}
        if isinstance(argument, ast.Name):
            return command_bindings.get(
                (lexical_scope_id(argument), argument.id),
                set(),
            )
        return set()

    def allowed_evidence_command(command: tuple[str, ...]) -> bool:
        if command in {("git", "rev-parse", "HEAD"), ("git", "status", "--porcelain")}:
            return True
        if command[:4] == ("docker", "login", "ghcr.io", "--username"):
            # The sole registry endpoint is fixed before the dynamic username.
            return True
        return any(
            len(command) >= len(prefix) and command[: len(prefix)] == prefix
            for prefix in ALLOWED_RELEASE_VALIDATOR_COMMAND_PREFIXES
            if prefix not in {("docker", "login"), ("git", "rev-parse"), ("git", "status")}
        )

    function_stack: list[str] = []

    def environment_path_target(target: ast.expr) -> bool:
        if isinstance(target, ast.Attribute):
            return qualified_name(target) in {"os.environ", "os.environb"}
        if not isinstance(target, ast.Subscript):
            return False
        if qualified_name(target.value) not in {"os.environ", "os.environb"}:
            return False
        key = target.slice
        return not (
            isinstance(key, ast.Constant)
            and isinstance(key.value, (bytes, str))
            and key.value not in {"PATH", b"PATH"}
        )

    def require_safe_defaults(node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = [*node.args.defaults, *node.args.kw_defaults]
        require(
            not any(
                value is not None and expression_has_restricted_callable(value)
                for value in defaults
            ),
            "release-intent validator binds a restricted callable as a function default",
        )

    class OperationsVisitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            require(
                not any(
                    qualified_name(base) == "urllib.request.Request"
                    for base in node.bases
                ),
                "release-intent validator subclasses the evidence request type",
            )
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            require_safe_defaults(node)
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            require_safe_defaults(node)
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def mutated_command_binding(self, target: ast.expr) -> bool:
            while isinstance(target, (ast.Attribute, ast.Subscript)):
                target = target.value
            return isinstance(target, ast.Name) and (
                lexical_scope_id(target), target.id
            ) in command_bindings

        def visit_Assign(self, node: ast.Assign) -> None:
            require(
                not any(
                    isinstance(target, (ast.Attribute, ast.Subscript))
                    and self.mutated_command_binding(target)
                    for target in node.targets
                ),
                "release-intent validator mutates an allowlisted command",
            )
            require(
                not any(environment_path_target(target) for target in node.targets),
                "release-intent validator mutates executable resolution",
            )
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            require(
                not environment_path_target(node.target),
                "release-intent validator mutates executable resolution",
            )
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            require(
                not self.mutated_command_binding(node.target),
                "release-intent validator mutates an allowlisted command",
            )
            require(
                not environment_path_target(node.target),
                "release-intent validator mutates executable resolution",
            )
            self.generic_visit(node)

        def visit_Return(self, node: ast.Return) -> None:
            if node.value is not None:
                require(
                    not any(
                        isinstance(value, ast.expr)
                        and restricted_callable_name(qualified_name(value))
                        for value in ast.walk(node.value)
                    ),
                    "release-intent validator returns a restricted callable",
                )
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            require(
                isinstance(node.func, (ast.Name, ast.Attribute)),
                "release-intent validator calls an unresolved callable expression",
            )
            qualified = qualified_name(node.func)
            require(
                not any(
                    expression_has_restricted_callable(value)
                    for value in [
                        *node.args,
                        *(keyword.value for keyword in node.keywords),
                    ]
                ),
                "release-intent validator forwards a restricted callable "
                f"at line {node.lineno}",
            )
            if isinstance(node.func, ast.Attribute):
                require(
                    not (
                        self.mutated_command_binding(node.func.value)
                        and node.func.attr
                        in {
                            "__delitem__",
                            "__iadd__",
                            "__imul__",
                            "__setitem__",
                            "clear",
                            "insert",
                            "pop",
                            "remove",
                            "reverse",
                            "sort",
                        }
                    ),
                    "release-intent validator mutates an allowlisted command "
                    f"at line {node.lineno}",
                )
            require(
                qualified
                not in {
                    "__import__",
                    "builtins.__import__",
                    "builtins.compile",
                    "builtins.eval",
                    "builtins.exit",
                    "builtins.exec",
                    "builtins.getattr",
                    "builtins.globals",
                    "builtins.locals",
                    "builtins.quit",
                    "builtins.setattr",
                    "builtins.vars",
                    "compile",
                    "eval",
                    "exit",
                    "exec",
                    "getattr",
                    "globals",
                    "importlib.import_module",
                    "locals",
                    "os._exit",
                    "object.__setattr__",
                    "os.putenv",
                    "os.unsetenv",
                    "quit",
                    "setattr",
                    "sys.exit",
                    "type.__setattr__",
                    "vars",
                }
                and qualified not in {"os.popen", "os.system"}
                and not qualified.endswith(
                    (".__delattr__", ".__delitem__", ".__setattr__", ".__setitem__")
                )
                and not is_os_process_launcher(qualified),
                "release-intent validator contains dynamic command execution",
            )
            if qualified.startswith(("os.environ.", "os.environb.")):
                method = qualified.rsplit(".", 1)[-1]
                require(
                    method not in {
                        "__delitem__",
                        "__setitem__",
                        "clear",
                        "pop",
                        "popitem",
                        "update",
                    },
                    "release-intent validator mutates executable resolution",
                )
                if method == "setdefault":
                    require(
                        bool(node.args)
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                        and node.args[0].value != "PATH",
                        "release-intent validator mutates executable resolution",
                    )
            if qualified.startswith("subprocess."):
                method = qualified.split(".", 1)[1]
                require(
                    method in allowed_subprocess_calls and bool(node.args),
                    "release-intent validator uses a non-allowlisted subprocess API",
                )
                commands = bound_commands(node.args[0])
                require(
                    bool(commands)
                    and all(allowed_evidence_command(command) for command in commands),
                    "release-intent validator executes a non-evidence command "
                    f"at line {node.lineno}: {sorted(commands)}",
                )
                require(
                    not any(
                        keyword.arg == "shell"
                        and not (
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is False
                        )
                        for keyword in node.keywords
                    ),
                    "release-intent validator enables a subprocess shell",
                )
            require(
                qualified not in prohibited_url_calls,
                "release-intent validator uses an unapproved network-opening API",
            )
            approved_url_call = qualified == "urllib.request.Request" or any(
                qualified == f"{name}.open" for name in opener_bindings
            )
            approved_local_open = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"
                and isinstance(node.func.value, ast.Call)
                and qualified_name(node.func.value.func) == "pathlib.Path"
            )
            require(
                not (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "open"
                    and not approved_url_call
                    and not approved_local_open
                ),
                "release-intent validator uses an unresolved opener",
            )
            if approved_url_call:
                require(
                    bool(function_stack)
                    and function_stack[-1] in {"api_request", "download_artifact_archive"},
                    "release-intent validator opens a URL outside the evidence clients",
                )
                require(
                    len(node.args) == 1
                    and not any(isinstance(argument, ast.Starred) for argument in node.args),
                    "evidence client uses unproved positional request arguments",
                )
                require(
                    all(keyword.arg is not None for keyword in node.keywords),
                    "evidence client uses unproved request keyword expansion",
                )
                for keyword in node.keywords:
                    if keyword.arg == "data":
                        require(
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is None,
                            "evidence client request must not contain a body",
                        )
                    if keyword.arg == "method":
                        require(
                            qualified == "urllib.request.Request"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value in {"GET", "HEAD"},
                            "evidence client request method must be provably read-only",
                        )
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            require(
                not (
                    node.attr == "__dict__"
                    or isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr
                    in {
                        "method",
                        "data",
                        "get_method",
                        "full_url",
                        "host",
                        "selector",
                        "type",
                        "origin_req_host",
                    }
                ),
                "evidence client mutates request method, body, or destination after construction",
            )
            self.generic_visit(node)

    OperationsVisitor().visit(tree)


def validate(contract: dict[str, Any]) -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", contract.get("repository", ""))
    repository_id_text = os.environ.get("GITHUB_REPOSITORY_ID")
    require(contract.get("schema_version") == SCHEMA, "contract schema mismatch")
    require(repository in EXPECTED_IDENTITIES, "repository is outside the protected catalog identity map")
    require(contract.get("repository") == repository, "repository identity mismatch")
    expected_id, expected_role, expected_deployment, expected_runtime = EXPECTED_IDENTITIES[repository]
    require(contract.get("repository_id") == expected_id, "stable repository ID mismatch")
    require(contract.get("role") == expected_role, "repository role contradicts the protected catalog")
    require(
        contract.get("deployment_authority") is expected_deployment,
        "deployment authority contradicts the protected catalog",
    )
    require(
        contract.get("runtime_mutation_authority") is expected_runtime,
        "runtime mutation authority contradicts the protected catalog",
    )
    if repository_id_text:
        require(repository_id_text.isdigit(), "GITHUB_REPOSITORY_ID is invalid")
        require(contract.get("repository_id") == int(repository_id_text), "stable repository ID mismatch")
    require(contract.get("default_branch") == "main", "default branch must be main")
    require(contract.get("release_intent_workflow") == ".github/workflows/manual-release-intent.yml", "intent workflow mismatch")
    require(contract.get("require_verified_commit") is True, "verified commits must be required")
    require(contract.get("required_check_app_id") == 15368, "required checks must be bound to GitHub Actions")

    checks = require_string_list(
        contract.get("required_checks"),
        "at least one exact-head check is required",
        nonempty=True,
    )
    require(len(checks) == len(set(checks)), "required checks contain duplicates")

    deployment_authority = contract.get("deployment_authority") is True
    runtime_mutation_authority = contract.get("runtime_mutation_authority")
    if not isinstance(runtime_mutation_authority, bool):
        raise ContractError("runtime mutation authority must be boolean")
    require(
        runtime_mutation_authority is (contract.get("role") == "infrastructure"),
        "only the infrastructure repository may hold runtime mutation authority",
    )
    supported = contract.get("supported_phases")
    if deployment_authority:
        require(supported == PHASES, "deployment authority must support the normalized phase sequence")
    else:
        require(supported == ["plan"], "non-deployment authority must be plan-only")

    artifacts = require_mapping(contract.get("artifact_policy"), "artifact policy is missing")
    minimum = artifacts.get("minimum_images")
    maximum = artifacts.get("maximum_images")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ContractError("image bounds must be integers")
    require(0 <= minimum <= maximum, "image bounds are invalid")
    require(minimum == maximum, "contract must declare an exact image count")
    repositories = require_string_list(
        artifacts.get("image_repositories"),
        "image repositories must match the exact image count",
    )
    require(len(repositories) == maximum, "image repositories must match the exact image count")
    require(len(repositories) == len(set(repositories)), "image repositories contain duplicates")
    require(
        all(
            isinstance(item, str)
            and re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+", item)
            for item in repositories
        ),
        "image repository is invalid",
    )
    (
        expected_repositories,
        expected_sbom,
        expected_provenance,
        expected_signature,
        expected_verifier,
        expected_storage,
    ) = EXPECTED_ARTIFACT_POLICIES[repository]
    require(
        minimum == maximum == len(expected_repositories)
        and repositories == list(expected_repositories),
        "artifact image policy contradicts the protected repository identity",
    )
    require(
        artifacts.get("require_sbom") is expected_sbom
        and artifacts.get("require_provenance") is expected_provenance
        and artifacts.get("require_signature") is expected_signature
        and artifacts.get("attestation_verifier") == expected_verifier
        and artifacts.get("attestation_storage") == expected_storage,
        "artifact supply-chain policy contradicts the protected repository identity",
    )
    require(artifacts.get("require_digest") is True, "digest-only images are mandatory")
    require(artifacts.get("allow_rebuild_after_staging") is False, "rebuild after staging is forbidden")
    require(artifacts.get("allow_retag_after_staging") is False, "retag after staging is forbidden")
    for field in ("require_sbom", "require_provenance", "require_signature"):
        require(type(artifacts.get(field)) is bool, f"{field} must be boolean")
    supply_chain_required = any(
        artifacts[field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    )
    if supply_chain_required:
        require(artifacts.get("attestation_verifier") in {"github", "cosign"}, "attestation verifier is missing")
        require(artifacts.get("attestation_storage") in {"github", "oci"}, "attestation storage is missing")
        require(
            artifacts.get("attestation_verifier") != "cosign" or artifacts.get("attestation_storage") == "oci",
            "Cosign attestations must use OCI storage",
        )
        signer_workflow = artifacts.get("signer_workflow")
        require(
            isinstance(signer_workflow, str)
            and signer_workflow.startswith(".github/workflows/")
            and signer_workflow.endswith((".yml", ".yaml"))
            and (ROOT / signer_workflow).is_file(),
            "signer workflow is missing or invalid",
        )
    if contract.get("role") == "canonical-middleware":
        require(
            artifacts.get("require_sbom") is True
            and artifacts.get("require_provenance") is True
            and artifacts.get("require_signature") is True
            and artifacts.get("attestation_verifier") == "cosign",
            "canonical middleware supply-chain requirements cannot be downgraded",
        )

    environments = require_mapping(contract.get("environments"), "environment policy is missing")
    expected_environments = {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }
    require(
        environments == expected_environments if deployment_authority else environments == {},
        "protected environment policy mismatch",
    )

    safety = require_mapping(contract.get("safety"), "safety controls are missing")
    require(set(safety) == SAFETY_KEYS, "safety controls are incomplete or unexpected")
    require(all(value is False for value in safety.values()), "every external/live effect must remain disabled")

    native = require_mapping(contract.get("native_workflows"), "native workflow policy must be an object")
    required_native = REQUIRED_NATIVE_WORKFLOWS.get(repository, {})
    require(
        all(native.get(name) == path for name, path in required_native.items()),
        "native workflow scope contradicts the protected repository mapping",
    )
    signer_workflow = artifacts.get("signer_workflow")
    if supply_chain_required:
        require(
            signer_workflow in native.values(),
            "signer workflow is outside the enforced native workflow scope",
        )
    for value in native.values():
        require(isinstance(value, str) and value.startswith(".github/workflows/") and value.endswith((".yml", ".yaml")), "native workflow path is invalid")
        path = ROOT / value
        require(path.is_file() and not path.is_symlink(), f"native workflow is missing or unsafe: {value}")
        workflow = path.read_text(encoding="utf-8")
        require_immutable_action_references(workflow, value)
        if (
            supply_chain_required
            and deployment_authority
            and maximum > 0
            and value == signer_workflow
        ):
            require_reachable_signer_workflow(workflow, value)
        if runtime_mutation_authority is False and (
            workflow_has_runtime_mutation(workflow, value)
            or workflow_has_image_publication(workflow, value)
        ):
            require_mutating_jobs_disabled(workflow, value)
    if runtime_mutation_authority is False:
        workflow_paths = sorted(
            path
            for pattern in ("*.yml", "*.yaml")
            for path in (ROOT / ".github/workflows").glob(pattern)
        )
        require(bool(workflow_paths), "repository has no workflows to enforce")
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_runtime_mutation(workflow, relative) or workflow_has_image_publication(
                workflow, relative
            ):
                require_mutating_jobs_disabled(workflow, relative)
    if repository == "appolon1908-hue/scrapper":
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_image_publication(workflow, relative):
                require_image_publishing_jobs_disabled(workflow, relative)

    require_string_list(contract.get("blockers"), "blockers must be non-empty strings")

    require(INTENT_PATH.is_file() and not INTENT_PATH.is_symlink(), "manual release-intent workflow is missing or unsafe")
    require(RELEASE_VALIDATOR_PATH.is_file() and not RELEASE_VALIDATOR_PATH.is_symlink(), "release-intent validator is missing or unsafe")
    intent = INTENT_PATH.read_text(encoding="utf-8")
    require(
        hashlib.sha256(intent.encode()).hexdigest() == MANUAL_RELEASE_INTENT_SHA256,
        "manual release-intent workflow exact-source hash drift",
    )
    release_validator = RELEASE_VALIDATOR_PATH.read_text(encoding="utf-8")
    validate_release_validator_trust_root(release_validator, repository)
    validate_release_validator_operations(release_validator)
    validate_release_validator_gate_rechecks(release_validator)
    for marker in (
        "runtime_contacted\": False",
        "production_changed\": False",
        "external_effects_enabled\": False",
        "[\"git\", \"rev-parse\", \"HEAD\"]",
        "required checks are not app-bound",
        "prior evidence hash mismatch",
        "--source-digest",
    ):
        require(marker in release_validator, f"release-intent safety marker is missing: {marker}")
    for marker in (
        "persist-credentials: false",
        "prior_evidence_run_id:",
        "protected_environment_approved == false",
        "protected_environment_job_completed = true",
    ):
        require(marker in intent, f"release-intent workflow marker is missing: {marker}")
    validate_intent_source_binding(intent)
    validate_protected_job_recheck(intent)
    require(
        not workflow_has_runtime_command(intent, ".github/workflows/manual-release-intent.yml"),
        "release-intent workflow contains a runtime/deployment command",
    )
    actions = workflow_actions(intent, ".github/workflows/manual-release-intent.yml")
    require(bool(actions) and set(actions) <= ALLOWED_ACTIONS, "release-intent workflow uses a non-allowlisted action")


def validate_negative_regressions(contract: dict[str, Any]) -> None:
    require_immutable_action_references(
        "jobs:\n  test:\n    uses: owner/repository/.github/workflows/check.yml@"
        "0123456789012345678901234567890123456789\n",
        "synthetic-immutable-action.yml",
    )
    try:
        require_immutable_action_references(
            "jobs:\n  test:\n    uses: owner/repository/.github/workflows/check.yml@v1\n",
            "synthetic-mutable-action.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: mutable action reference"
        )
    reachable_signer = """jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - id: build
        uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: true
          tags: ghcr.io/example/repository:sha-0123456
      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'
"""
    require_reachable_signer_workflow(
        reachable_signer,
        "synthetic-reachable-signer.yml",
    )
    symbolic_signer = """jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - id: build
        uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: true
          tags: ghcr.io/example/${{ matrix.repository }}:sha-0123456
      - uses: actions/attest-build-provenance@0123456789012345678901234567890123456789
        with:
          subject-name: ghcr.io/example/${{ matrix.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
"""
    require_reachable_signer_workflow(
        symbolic_signer,
        "synthetic-symbolic-signer.yml",
    )
    try:
        require_reachable_signer_workflow(
            symbolic_signer.replace(
                "subject-name: ghcr.io/example/${{ matrix.repository }}",
                "subject-name: ghcr.io/example/${{ matrix.other }}",
            ),
            "synthetic-symbolic-subject-mismatch.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: symbolic subject mismatch"
        )
    for disabled_condition in (
        "false",
        "'false'",
        "${{ false }}",
        "0",
        "${{ false && true }}",
        "${{ 1 == 2 }}",
        "${{ false == true }}",
        "${{ true != true }}",
        "${{ 'a' == 'b' }}",
        "${{ (false) == true }}",
        "${{ 'a' == ('b') }}",
        "${{ false && github.ref == 'refs/heads/main' }}",
    ):
        try:
            require_reachable_signer_workflow(
                reachable_signer.replace(
                    "    runs-on: ubuntu-latest",
                    f"    if: {disabled_condition}\n    runs-on: ubuntu-latest",
                ),
                "synthetic-disabled-signer.yml",
            )
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: unreachable signer workflow"
            )
    disabled_publication_step = reachable_signer.replace(
        "      - id: build\n        uses: docker/build-push-action@",
        "      - id: build\n        if: false\n        uses: docker/build-push-action@",
        1,
    )
    try:
        require_reachable_signer_workflow(
            disabled_publication_step,
            "synthetic-disabled-publication-step.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: disabled publication step"
        )
    comment_only_attestation = reachable_signer.replace(
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "      - run: echo done # cosign attest",
        1,
    )
    try:
        require_reachable_signer_workflow(
            comment_only_attestation,
            "synthetic-comment-only-attestation.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: comment-only attestation"
        )
    for command in (
        "if false; then cosign attest --yes image@example; fi",
        "false && cosign attest --yes image@example",
        "true || cosign attest --yes image@example",
        "echo cosign attest --yes image@example",
    ):
        require(
            not step_has_reachable_attestation({"run": command}),
            "unreachable shell attestation was accepted",
        )
    require(
        not attestation_covers_publication(
            {"if": "${{ !inputs.publish }}"},
            {"if": "inputs.publish"},
        ),
        "complementary attestation condition was accepted",
    )
    require(
        attestation_covers_publication(
            {"if": "${{ inputs.publish }}"},
            {"if": "inputs.publish"},
        ),
        "identical publication/attestation conditions were rejected",
    )
    require(
        attestation_covers_publication({}, {"if": "inputs.publish"}),
        "unconditional attestation was rejected",
    )
    complementary_signer = reachable_signer.replace(
        "      - id: build\n        uses: docker/build-push-action@",
        "      - id: build\n        if: inputs.publish\n        uses: docker/build-push-action@",
    ).replace(
        "      - run: cosign attest",
        "      - if: ${{ !inputs.publish }}\n        run: cosign attest",
    )
    try:
        require_reachable_signer_workflow(
            complementary_signer,
            "synthetic-complementary-signer.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: unattested publication path"
        )
    unreachable_cosign = reachable_signer.replace(
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "      - run: if false; then cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'; fi",
        1,
    )
    try:
        require_reachable_signer_workflow(
            unreachable_cosign,
            "synthetic-unreachable-cosign-signer.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: unreachable cosign attestation"
        )
    mismatched_attestation = reachable_signer.replace(
        "cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "cosign attest --yes ghcr.io/example/other:sha-0123456",
        1,
    )
    try:
        require_reachable_signer_workflow(
            mismatched_attestation,
            "synthetic-mismatched-attestation.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: attestation subject mismatch"
        )
    mixed_attestation = reachable_signer.replace(
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'\n"
        "      - run: cosign attest --yes ghcr.io/example/other:sha-0123456",
        1,
    )
    try:
        require_reachable_signer_workflow(
            mixed_attestation,
            "synthetic-mixed-attestation.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: extra unbound attestation"
        )
    partial_multi_subject = reachable_signer.replace(
        "          tags: ghcr.io/example/repository:sha-0123456",
        "          tags: |\n"
        "            ghcr.io/example/repository:sha-0123456\n"
        "            ghcr.io/example/secondary:sha-0123456",
        1,
    )
    try:
        require_reachable_signer_workflow(
            partial_multi_subject,
            "synthetic-partial-multi-subject.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: partially attested publication"
        )
    complete_multi_subject = partial_multi_subject.replace(
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'\n"
        "      - run: cosign attest --yes 'ghcr.io/example/secondary@${{ steps.build.outputs.digest }}'",
        1,
    )
    require_reachable_signer_workflow(
        complete_multi_subject,
        "synthetic-complete-multi-subject.yml",
    )
    immutable_subject = "ghcr.io/example/repository@sha256:" + "a" * 64
    environment_signer = f"""jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - env:
          IMAGE: {immutable_subject}
        run: docker push "$IMAGE"
      - env:
          IMAGE: {immutable_subject}
        run: cosign attest --yes "$IMAGE"
"""
    require_reachable_signer_workflow(
        environment_signer,
        "synthetic-matching-step-environment.yml",
    )
    try:
        require_reachable_signer_workflow(
            environment_signer.replace(
                f"          IMAGE: {immutable_subject}\n        run: cosign",
                "          IMAGE: ghcr.io/example/other@sha256:"
                + "b" * 64
                + "\n        run: cosign",
                1,
            ),
            "synthetic-conflicting-step-environment.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: conflicting subject environment"
        )
    premature_attestation = """jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'
      - id: build
        uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: true
          tags: ghcr.io/example/repository:sha-0123456
"""
    try:
        require_reachable_signer_workflow(
            premature_attestation,
            "synthetic-premature-attestation.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: attestation preceded publication"
        )
    action_attestation = reachable_signer.replace(
        "      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'",
        "      - uses: actions/attest@0123456789012345678901234567890123456789\n"
        "        with:\n"
        "          subject-name: ghcr.io/example/repository\n"
        "          subject-digest: ${{ steps.build.outputs.digest }}",
        1,
    )
    require_reachable_signer_workflow(
        action_attestation,
        "synthetic-action-attestation.yml",
    )
    split_attestation = """jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: true
  attest:
    if: false
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest@0123456789012345678901234567890123456789
"""
    try:
        require_reachable_signer_workflow(
            split_attestation,
            "synthetic-detached-attestation.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: detached attestation"
        )
    mutations = []

    missing_check = deepcopy(contract)
    missing_check["required_checks"] = []
    mutations.append(("missing required checks", missing_check))

    wrong_check_app = deepcopy(contract)
    wrong_check_app["required_check_app_id"] = 1
    mutations.append(("wrong required-check app", wrong_check_app))

    mutable_retag = deepcopy(contract)
    mutable_retag["artifact_policy"]["allow_retag_after_staging"] = True
    mutations.append(("mutable retag", mutable_retag))

    incomplete_images = deepcopy(contract)
    incomplete_images["artifact_policy"]["minimum_images"] = (
        incomplete_images["artifact_policy"]["maximum_images"] + 1
    )
    mutations.append(("invalid image bounds", incomplete_images))

    wrong_repositories = deepcopy(contract)
    wrong_repositories["artifact_policy"]["image_repositories"] = [
        "ghcr.io/example/wrong"
    ] * (wrong_repositories["artifact_policy"]["maximum_images"] + 1)
    mutations.append(("incorrect image repositories", wrong_repositories))

    identity_artifact_downgrade = deepcopy(contract)
    identity_artifact_downgrade["artifact_policy"].update(
        {
            "minimum_images": 0,
            "maximum_images": 0,
            "image_repositories": [],
            "require_sbom": False,
            "require_provenance": False,
            "require_signature": False,
            "attestation_verifier": None,
            "attestation_storage": None,
        }
    )
    if contract["artifact_policy"]["maximum_images"] != 0:
        mutations.append(("repository artifact-policy downgrade", identity_artifact_downgrade))

    live_effect = deepcopy(contract)
    live_effect["safety"]["payment_execution"] = True
    mutations.append(("enabled live effect", live_effect))

    phase_escalation = deepcopy(contract)
    phase_escalation["deployment_authority"] = False
    phase_escalation["supported_phases"] = PHASES
    mutations.append(("non-authority phase escalation", phase_escalation))

    runtime_escalation = deepcopy(contract)
    runtime_escalation["runtime_mutation_authority"] = not runtime_escalation["runtime_mutation_authority"]
    mutations.append(("runtime mutation authority contradiction", runtime_escalation))

    role_escalation = deepcopy(contract)
    role_escalation["role"] = (
        "application" if contract.get("role") == "infrastructure" else "infrastructure"
    )
    role_escalation["runtime_mutation_authority"] = (
        role_escalation["role"] == "infrastructure"
    )
    mutations.append(("self-declared infrastructure authority", role_escalation))

    missing_native = deepcopy(contract)
    missing_native["native_workflows"] = {
        "invalid": ".github/workflows/does-not-exist.yml"
    }
    mutations.append(("missing native workflow", missing_native))

    if any(
        contract["artifact_policy"][field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    ):
        supply_chain_downgrade = deepcopy(contract)
        supply_chain_downgrade["artifact_policy"]["attestation_verifier"] = "none"
        mutations.append(("supply-chain verifier downgrade", supply_chain_downgrade))

    python_mutation_regressions = {
        "socket-backed file writer": (
            "import socket\ns=socket.socket(); f=s.makefile('wb'); f.write(b'x')\n"
        ),
        "socket sendmsg": "import socket\ns=socket.socket(); s.sendmsg([b'x'])\n",
        "socket sendfile": (
            "import socket\ns=socket.socket(); s.sendfile(open('x','rb'))\n"
        ),
        "TLS-wrapped socket writer": (
            "import socket, ssl\n"
            "channel=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket(socket.socket())\n"
            "channel.connect(('runtime.example',443)); channel.write(b'x')\n"
        ),
        "asyncio stream writer": (
            "import asyncio\nasync def send():\n"
            " r,w=await asyncio.open_connection('host',443); w.write(b'x'); await w.drain()\n"
        ),
        "ctypes launcher": "import ctypes\nctypes.CDLL(None).system(b'kubectl apply -f x')\n",
        "pty launcher": "import pty\npty.spawn(['kubectl','apply','-f','x'])\n",
        "runpy loader": "import runpy\nrunpy.run_path('deploy.py')\n",
        "XML-RPC client": (
            "import xmlrpc.client\n"
            "api=xmlrpc.client.ServerProxy('https://runtime.example/RPC2')\n"
            "api.deploy({'production': True})\n"
        ),
        "returned callable": (
            "import subprocess\ndef launcher(): return subprocess.run\n"
            "runner=launcher(); runner(['kubectl','apply','-f','x'])\n"
        ),
        "container-returned callable": (
            "import subprocess as s\nrunner=[s.run][0]\n"
            "runner(['kubectl','apply','-f','x'])\n"
        ),
        "unresolved database writer": (
            "import psycopg\nc=psycopg.connect('dsn'); c.execute('DELETE FROM x'); c.commit()\n"
        ),
        "MongoDB writer": (
            "import pymongo\nclient=pymongo.MongoClient('mongodb://runtime')\n"
            "client.db.users.delete_many({})\n"
        ),
        "FTP writer": (
            "import ftplib\nftp=ftplib.FTP('runtime')\n"
            "ftp.storbinary('STOR payload', open('payload','rb'))\n"
        ),
        "posix launcher": "import posix\nposix.system('kubectl apply -f x')\n",
        "mutated command binding": (
            "import subprocess\ncmd=['echo']; cmd.clear(); "
            "cmd.extend(['kubectl','apply']); subprocess.run(cmd)\n"
        ),
        "lambda socket factory": (
            "import socket\nfactory=lambda: socket.socket(); "
            "channel=factory(); channel.sendto(b'x', ('runtime', 9))\n"
        ),
    }
    for name, source in python_mutation_regressions.items():
        require(
            python_source_has_runtime_mutation(source),
            f"Python mutation regression escaped: {name}",
        )

    javascript_mutation_regressions = {
        "optional loader": (
            "const t=require?.('node:'+'https'); "
            "t.request(url,{method:'POST'}).end(data)"
        ),
        "createRequire loader": (
            "import {createRequire} from 'node:module'; const r=createRequire(import.meta.url); "
            "r('child_process').execSync('kubectl apply -f x')"
        ),
        "datagram sender": (
            "const d=require('node:dgram'); const s=d.createSocket('udp4'); "
            "s.send('x',1,'host')"
        ),
        "computed WebSocket send": (
            "const ws=new WebSocket(url); ws['send'](payload)"
        ),
        "computed global fetch": (
            "globalThis['fe'+'tch'](url,{method:'POST',body:data})"
        ),
    }
    for name, source in javascript_mutation_regressions.items():
        require(
            javascript_source_has_runtime_mutation(source),
            f"JavaScript mutation regression escaped: {name}",
        )

    for command in (
        "kubectl edit deployment/api",
        "kubectl debug node/runtime-node --image=busybox",
        "prlimit -- kubectl apply -f runtime.yml",
        "parallel sh -c 'kubectl apply -f runtime.yml' -- one",
        "run-parts ./runtime-hooks",
        "setpriv --no-new-privs kubectl apply -f runtime.yml",
        "sg runtime -c 'kubectl apply -f runtime.yml'",
        "sudo su -c 'kubectl apply -f runtime.yml'",
        "docker stop prod",
        "podman restart prod",
        'op=run; docker "$op" --rm image',
        "PATH=./tools:$PATH git status",
        "printf 'BASH_ENV=/tmp/hook\\n' >> \"$GITHUB_ENV\"",
        "NODE_OPTIONS=--require=./mutate.cjs node -e '0'",
        "python3 -m django migrate --settings=CORE.settings",
    ):
        require(
            contains_runtime_mutation(command),
            f"shell mutation regression escaped: {command}",
        )

    startup_environment_workflows = {
        "workflow": """env:
  BASH_ENV: ./.codestra/runtime-deploy.sh
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - run: echo harmless
""",
        "job": """jobs:
  validate:
    runs-on: ubuntu-latest
    env:
      BASH_ENV: ./.codestra/runtime-deploy.sh
    steps:
      - run: echo harmless
""",
        "step": """jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - env:
          BASH_ENV: ./.codestra/runtime-deploy.sh
        run: echo harmless
""",
    }
    for scope, workflow in startup_environment_workflows.items():
        require(
            workflow_has_runtime_mutation(
                workflow,
                f"synthetic-{scope}-startup-environment.yml",
            ),
            f"{scope} startup environment regression escaped",
        )

    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        helper = Path(directory) / "helper.py"
        caller = Path(directory) / "caller.py"
        helper.write_text(
            "import requests\ndef deploy(): requests.post('https://runtime.example')\n",
            encoding="utf-8",
        )
        caller.write_text("import helper\nhelper.deploy()\n", encoding="utf-8")
        require(
            repository_script_path_has_runtime_mutation(
                caller,
                set(),
                None,
                Path(directory),
            ),
            "invoked imported helper body escaped mutation classification",
        )

    signer_regressions = {
        "partially attested multi-subject publication": reachable_signer.replace(
            "tags: ghcr.io/example/repository:sha-0123456",
            "tags: |\n            ghcr.io/example/repository:sha-0123456\n"
            "            ghcr.io/example/other:sha-0123456",
        ),
        "step-local dynamic subject mismatch": """jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: docker push "$IMAGE"
        env: {IMAGE: ghcr.io/example/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
      - run: cosign attest --yes "$IMAGE"
        env: {IMAGE: ghcr.io/example/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}
""",
        "publication blocked by dependency": """jobs:
  prerequisite:
    if: false
    runs-on: ubuntu-latest
    steps: [{run: echo blocked}]
  publish:
    needs: prerequisite
    runs-on: ubuntu-latest
    steps:
      - id: build
        uses: docker/build-push-action@0123456789012345678901234567890123456789
        with: {push: true, tags: ghcr.io/example/repository:sha-0123456}
      - run: cosign attest --yes 'ghcr.io/example/repository@${{ steps.build.outputs.digest }}'
""",
    }
    for name, workflow in signer_regressions.items():
        try:
            require_reachable_signer_workflow(workflow, f"synthetic-{name}.yml")
        except ContractError:
            pass
        else:
            raise ContractError(f"signer regression unexpectedly passed: {name}")

    for name, mutation in mutations:
        try:
            validate(mutation)
        except ContractError:
            continue
        raise ContractError(f"negative regression unexpectedly passed: {name}")


def validate_intent_negative_regressions(contract: dict[str, Any]) -> None:
    intent = INTENT_PATH.read_text(encoding="utf-8")
    release_validator = RELEASE_VALIDATOR_PATH.read_text(encoding="utf-8")
    executable_binding = re.sub(
        r'SHARED_PRODUCTION_VALIDATOR_SHA256 = \(\n(?:    "[0-9a-f]{32}"\n){2}\)',
        "SHARED_PRODUCTION_VALIDATOR_SHA256 = compute_untrusted_hash()",
        release_validator,
        count=1,
    )
    require(executable_binding != release_validator, "executable trust-binding fixture is missing")
    try:
        validate_release_validator_trust_root(
            executable_binding,
            contract.get("repository"),
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: executable release-validator trust binding"
        )
    shared_line_injection = re.sub(
        r'(SHARED_PRODUCTION_VALIDATOR_SHA256 = \(\n(?:    "[0-9a-f]{32}"\n){2}\))',
        r"\1; INDEPENDENT_REVIEWER_ID = 1",
        release_validator,
        count=1,
    )
    require(
        shared_line_injection != release_validator,
        "shared-line trust-binding fixture is missing",
    )
    try:
        validate_release_validator_trust_root(
            shared_line_injection,
            contract.get("repository"),
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: shared-line trust-binding injection"
        )
    supply_chain_bypass = release_validator.replace(
        ") -> None:\n    require_sbom = policy.get(\"require_sbom\")",
        ") -> None:\n    return\n    require_sbom = policy.get(\"require_sbom\")",
        1,
    )
    require(supply_chain_bypass != release_validator, "supply-chain bypass fixture is missing")
    try:
        validate_release_validator_trust_root(
            supply_chain_bypass,
            contract.get("repository"),
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: release-validator supply-chain bypass"
        )
    unreachable_recheck = release_validator.replace(
        "\n    final_controller_candidate_head = download_and_validate_candidate(",
        "\n    if False:\n        final_controller_candidate_head = download_and_validate_candidate(",
        1,
    )
    require(
        unreachable_recheck != release_validator,
        "unreachable gate-recheck fixture is missing",
    )
    try:
        validate_release_validator_gate_rechecks(unreachable_recheck)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: unreachable final gate recheck"
        )
    unsafe_intents = (
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs['source_sha'] }}",
            1,
        ),
        intent.replace(
            "          ref: ${{ github.sha }}",
            "          # ref: ${{ github.sha }}\n          ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            '          test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            '          # test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            1,
        ),
    )
    for unsafe in unsafe_intents:
        try:
            validate_intent_source_binding(unsafe)
        except ContractError:
            continue
        raise ContractError("negative regression unexpectedly passed: unsafe source binding")
    unsafe_protected_job = intent.replace(
        "    environment:\n      name: ${{ needs.verify.outputs.environment }}",
        "    environment: unreviewed-production",
        1,
    )
    try:
        validate_protected_job_recheck(unsafe_protected_job)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: protected environment binding"
        )
    for binding in (
        "          PRIOR_EVIDENCE_SHA256: ${{ inputs.prior_evidence_sha256 }}\n",
        "          PRIOR_EVIDENCE_RUN_ID: ${{ inputs.prior_evidence_run_id }}\n",
        "          PREAPPROVAL_EVIDENCE_B64: ${{ needs.verify.outputs.evidence_b64 }}\n",
    ):
        prefix, separator, suffix = intent.rpartition(binding)
        require(bool(separator), "protected prior evidence binding fixture is missing")
        unsafe_protected_job = prefix + suffix
        try:
            validate_protected_job_recheck(unsafe_protected_job)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: incomplete protected prior evidence binding"
            )
    for command in (
        "helm upgrade release chart",
        "kubectl apply -f runtime.yml",
        "terraform apply",
        "tofu destroy",
        "ssh runtime.example true",
        "ansible-playbook production.yml",
        "./apply-plan.sh",
        "command docker pull example.invalid/image",
        'echo "$TOKEN" | docker login ghcr.io',
        "bash -c 'kubectl apply -f runtime.yml'",
        "sh -c 'terraform apply'",
        "eval 'helm upgrade release chart'",
        "nice kubectl apply -f runtime.yml",
        "ionice kubectl apply -f runtime.yml",
        "setsid kubectl apply -f runtime.yml",
        "systemd-run --wait kubectl apply -f runtime.yml",
        "TOOL=$(echo kubectl); \"$TOOL\" apply -f runtime.yml",
        "echo validation\n\ngh api --method POST repos/example/runtime/dispatches",
        "GIT_ALLOW_PROTOCOL=ext git fetch ext::sh\\ -c\\ id",
        "printf './deploy.sh\\n' | xargs bash",
        "trap 'kubectl apply -f runtime.yml' EXIT",
        "sh -s <<< 'kubectl apply -f runtime.yml'",
    ):
        require(
            contains_runtime_command(command),
            f"negative runtime command regression passed: {command}",
        )
    require(
        not contains_runtime_command("# docker pull example.invalid/image"),
        "comment-only runtime command was treated as executable",
    )
    if (ROOT / "scripts/apply_repository_governance.py").is_file():
        require(
            not contains_runtime_mutation(
                "python3 scripts/apply_repository_governance.py"
            ),
            "governance plan invocation was treated as runtime mutation",
        )
        require(
            not contains_runtime_mutation(
                "python3 scripts/apply_repository_governance.py --apply"
            ),
            "repository-control-plane apply was treated as runtime mutation",
        )
        require(
            contains_runtime_mutation(
                "python3 scripts/apply_repository_governance.py --apply --unexpected"
            ),
            "unapproved governance invocation escaped runtime-mutation classification",
        )
        require(
            not contains_runtime_mutation(
                "python3 scripts/apply_repository_governance.py --verify-live"
            ),
            "read-only governance verification was treated as runtime mutation",
        )
    repository = "ingtrader21-spec/Middleware-"
    control_plane_paths: tuple[str, ...] = (
        ".github/workflows/integration-main-release-authorities.yml",
        ".github/workflows/production-reviewer-access.yml",
    )
    if not all((ROOT / path).is_file() for path in control_plane_paths):
        control_plane_paths = ()
    for workflow_path in control_plane_paths:
        workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
        require(
            not workflow_has_runtime_mutation(workflow, workflow_path),
            f"approved repository control-plane workflow was treated as runtime: {workflow_path}",
        )
        require(
            workflow_has_runtime_mutation(
                workflow.replace(
                    "CONTROL_PLANE_MUTATION=repository-administration",
                    "CONTROL_PLANE_MUTATION=unreviewed",
                    1,
                ),
                workflow_path,
            ),
            f"control-plane workflow hash drift escaped classification: {workflow_path}",
        )
        trusted = verified_control_plane_dependencies(repository, workflow_path)
        require(
            trusted is not None and bool(trusted),
            f"control-plane dependency manifest is missing: {workflow_path}",
        )
        assert trusted is not None
        entry_script = (
            "scripts/apply_integration_main_release_authorities_v2.py"
            if workflow_path.endswith("integration-main-release-authorities.yml")
            else "scripts/apply_production_reviewer_access.py"
        )
        require(
            not script_dependencies_have_runtime_mutation(
                f"python3 -I {entry_script} --mode validate",
                {},
                ROOT,
                trusted,
            ),
            f"isolated trusted control-plane script was rejected: {entry_script}",
        )
        require(
            script_dependencies_have_runtime_mutation(
                f"python3 {entry_script} --mode validate",
                {},
                ROOT,
                trusted,
            ),
            f"non-isolated trusted control-plane script escaped: {entry_script}",
        )
        dependency_manifest = APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256[repository][
            workflow_path
        ]
        dependency_path = next(iter(dependency_manifest))
        expected_hash = dependency_manifest[dependency_path]
        dependency_manifest[dependency_path] = "0" * 64
        try:
            require(
                verified_control_plane_dependencies(repository, workflow_path) is None,
                f"control-plane dependency drift escaped classification: {workflow_path}",
            )
        finally:
            dependency_manifest[dependency_path] = expected_hash
    require(
        contract.get("repository") != repository
        or not contains_runtime_mutation("bash scripts/run_ci.sh"),
        "validation script dependency chain was treated as runtime mutation",
    )
    enabled_mutation = """name: synthetic
jobs:
  deploy:
    # RUNTIME_MUTATION_DISABLED=true
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
"""
    try:
        require_mutating_jobs_disabled(enabled_mutation, "synthetic.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: enabled mutating job")
    enabled_service = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    services:
      writer:
        image: example.invalid/runtime-writer:latest
    steps:
      - run: echo validation
"""
    try:
        require_mutating_jobs_disabled(enabled_service, "synthetic-service.yml")
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: executable job service"
        )
    enabled_action_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses : vendor/kubernetes-deploy@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(enabled_action_mutation, "synthetic-action.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: action mutating job")
    quoted_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: "ssh runtime.example deploy"
"""
    try:
        require_mutating_jobs_disabled(quoted_mutation, "synthetic-quoted.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: quoted mutating command")
    github_script_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await exec.exec('kubectl', ['apply', '-f', 'runtime.yml'])
"""
    try:
        require_mutating_jobs_disabled(github_script_mutation, "synthetic-github-script.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: github-script mutation")
    octokit_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await github.rest.repos.createDeployment({owner, repo, ref})
"""
    try:
        require_mutating_jobs_disabled(octokit_mutation, "synthetic-octokit.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: Octokit mutation")
    github_request_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await github.request('POST /repos/{owner}/{repo}/deployments')
"""
    try:
        require_mutating_jobs_disabled(
            github_request_mutation,
            "synthetic-github-request.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: GitHub request mutation"
        )
    for name, script in (
        (
            "GitHub GraphQL mutation",
            "await github.graphql('mutation { createDeployment(input: {}) { id } }')",
        ),
        (
            "aliased GitHub request",
            "const write = github.request; "
            "await write('POST /repos/{owner}/{repo}/deployments')",
        ),
        (
            "aliased GitHub REST mutation",
            "const write = github.rest.issues.createComment; "
            "await write({owner, repo, issue_number, body: 'changed'})",
        ),
        (
            "bracket-aliased GitHub GraphQL",
            "const gql = github['graphql']; "
            "await gql('mutation { createDeployment(input: {}) { id } }')",
        ),
        (
            "bracket-accessed GitHub request",
            "await github['request']('POST /repos/{owner}/{repo}/deployments')",
        ),
        (
            "bracket-accessed GitHub REST mutation",
            "await github['rest']['issues']['create']({owner, repo})",
        ),
        (
            "destructured GitHub REST mutation",
            "const {createDeployment} = github.rest.repos; "
            "await createDeployment({owner, repo, ref})",
        ),
        (
            "computed GitHub workflow dispatch",
            "await github.rest.actions['create' + 'WorkflowDispatch']({owner, repo})",
        ),
        (
            "optional-chain GitHub REST mutation",
            "await github?.rest.repos.createDeployment({owner, repo, ref})",
        ),
        (
            "whitespace-separated GitHub REST mutation",
            "await github\n .rest . repos . createDeployment({owner, repo, ref})",
        ),
        (
            "aliased GitHub client mutation",
            "const client = github; "
            "await client.rest.actions.createWorkflowDispatch({owner, repo})",
        ),
        (
            "copied GitHub client mutation",
            "const client = Object.assign({}, github); "
            "await client.rest.issues.create({owner, repo})",
        ),
        (
            "nested copied GitHub client mutation",
            "const client = Object.assign(Object.create(null), github); "
            "await client.rest.issues.create({owner, repo})",
        ),
        (
            "parenthesized proxied GitHub client mutation",
            "const client = new Proxy((github), {}); "
            "await client.rest.issues.create({owner, repo})",
        ),
        (
            "reflective GitHub client mutation",
            "const rest = Reflect.get(github, 'rest'); "
            "await rest.repos.createDeployment({owner, repo, ref})",
        ),
        (
            "spread GitHub client mutation",
            "const client = {...github}; "
            "await client.rest.issues.create({owner, repo})",
        ),
    ):
        workflow = f"""name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: {script}
"""
        try:
            require_mutating_jobs_disabled(workflow, "synthetic-github-writer.yml")
        except ContractError:
            pass
        else:
            raise ContractError(
                f"negative regression unexpectedly passed: {name}"
            )
    dynamic_publication = """name: synthetic
jobs:
  publish:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: ${{ true }}
"""
    try:
        require_image_publishing_jobs_disabled(
            dynamic_publication,
            "synthetic-dynamic-publication.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: dynamic image publication"
        )
    registry_export_publication = """name: synthetic
jobs:
  publish:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          outputs: type=registry,name=ghcr.io/example/image
"""
    try:
        require_image_publishing_jobs_disabled(
            registry_export_publication,
            "synthetic-registry-export-publication.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: registry exporter publication"
        )
    python_shell_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import subprocess
          subprocess.run(["kubectl", "apply", "-f", "runtime.yml"])
"""
    try:
        require_mutating_jobs_disabled(
            python_shell_mutation,
            "synthetic-python-shell.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: declared Python shell")
    workflow_python_shell_mutation = """name: synthetic
defaults:
  run:
    shell: python
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: urllib.request.urlopen(url, data=b'x')
"""
    try:
        require_mutating_jobs_disabled(
            workflow_python_shell_mutation,
            "synthetic-workflow-python-shell.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: workflow-level Python shell"
        )
    require(
        workflow_has_runtime_command(
            python_shell_mutation,
            "synthetic-release-intent-python-shell.yml",
        ),
        "negative release-intent Python shell regression passed",
    )
    pinned_parser_setup = f"""name: synthetic
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: {PINNED_WORKFLOW_PARSER_INSTALL}
"""
    require(
        not workflow_has_runtime_command(
            pinned_parser_setup,
            "synthetic-pinned-parser-setup.yml",
        ),
        "exact pinned parser setup was treated as governed-runtime contact",
    )
    for unsafe_parser_setup in (
        "python3 -m pip install PyYAML==6.0.3",
        f"{PINNED_WORKFLOW_PARSER_INSTALL} && curl https://runtime.example",
    ):
        unsafe_parser_workflow = f"""name: synthetic
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: {unsafe_parser_setup}
"""
        require(
            workflow_has_runtime_command(
                unsafe_parser_workflow,
                "synthetic-unsafe-parser-setup.yml",
            ),
            f"unsafe parser setup escaped contact classification: {unsafe_parser_setup}",
        )
    read_only_runtime_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          kubectl get pods
          docker inspect middleware-api
"""
    require(
        workflow_has_runtime_command(
            read_only_runtime_contact,
            "synthetic-release-intent-runtime-read.yml",
        ),
        "negative release-intent read-only runtime regression passed",
    )
    python_runtime_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import subprocess
          subprocess.run(["kubectl", "get", "pods"], check=True)
"""
    require(
        workflow_has_runtime_command(
            python_runtime_contact,
            "synthetic-release-intent-python-runtime-read.yml",
        ),
        "declared Python read-only runtime contact escaped classification",
    )
    node_runtime_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: node
        run: await fetch("https://runtime.example/health")
"""
    require(
        workflow_has_runtime_command(
            node_runtime_contact,
            "synthetic-release-intent-node-runtime-read.yml",
        ),
        "declared Node read-only runtime contact escaped classification",
    )
    invoked_runtime_reader = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: python3 scripts/audit_release_endpoints.py
"""
    require(
        workflow_has_runtime_command(
            invoked_runtime_reader,
            "synthetic-release-intent-invoked-runtime-read.yml",
        ),
        "invoked read-only runtime script escaped classification",
    )
    for client_command in (
        'curl -fsS "$RUNTIME_HEALTH_URL"',
        'wget -qO- "$RUNTIME_HEALTH_URL"',
    ):
        generic_network_contact = f"""name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: {client_command}
"""
        require(
            workflow_has_runtime_command(
                generic_network_contact,
                "synthetic-release-intent-generic-network-read.yml",
            ),
            f"generic network client escaped contact classification: {client_command}",
        )
    asyncio_runtime_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import asyncio
          asyncio.run(asyncio.open_connection(host, 443))
"""
    require(
        workflow_has_runtime_command(
            asyncio_runtime_contact,
            "synthetic-release-intent-asyncio-runtime-read.yml",
        ),
        "asyncio network connection escaped contact classification",
    )
    dynamic_node_runtime_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: node
        run: import("https").then(({get}) => get(process.env.RUNTIME_URL))
"""
    require(
        workflow_has_runtime_command(
            dynamic_node_runtime_contact,
            "synthetic-release-intent-dynamic-node-runtime-read.yml",
        ),
        "dynamic Node network import escaped contact classification",
    )
    python_generic_client_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import subprocess
          subprocess.run(["curl", "-fsS", "https://runtime.example/health"])
"""
    require(
        workflow_has_runtime_command(
            python_generic_client_contact,
            "synthetic-release-intent-python-generic-network-read.yml",
        ),
        "Python-launched generic network client escaped contact classification",
    )
    asyncio_subprocess_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import asyncio
          asyncio.run(asyncio.create_subprocess_exec("curl", "https://runtime.example"))
"""
    require(
        workflow_has_runtime_command(
            asyncio_subprocess_contact,
            "synthetic-release-intent-asyncio-subprocess-read.yml",
        ),
        "asyncio subprocess runtime contact escaped classification",
    )
    computed_commonjs_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: node
        run: |
          const transport = require("node:" + "https");
          transport.get(process.env.RUNTIME_URL);
"""
    require(
        workflow_has_runtime_command(
            computed_commonjs_contact,
            "synthetic-release-intent-computed-commonjs-runtime-read.yml",
        ),
        "computed CommonJS network import escaped contact classification",
    )
    commented_commonjs_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: node
        run: |
          const transport = require /*comment*/ ("https");
          transport.get(process.env.RUNTIME_URL);
"""
    require(
        workflow_has_runtime_command(
            commented_commonjs_contact,
            "synthetic-release-intent-commented-commonjs-runtime-read.yml",
        ),
        "comment-separated CommonJS import escaped contact classification",
    )
    bash_network_device_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: bash
        run: exec 3<>/dev/tcp/runtime.example/443
"""
    require(
        workflow_has_runtime_command(
            bash_network_device_contact,
            "synthetic-release-intent-bash-network-device-read.yml",
        ),
        "Bash network-device redirection escaped contact classification",
    )
    expanded_bash_network_device_contact = """name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: bash
        run: proto=tcp; exec 3<>/dev/$proto/runtime.example/443
"""
    require(
        workflow_has_runtime_command(
            expanded_bash_network_device_contact,
            "synthetic-release-intent-expanded-bash-network-device-read.yml",
        ),
        "expanded Bash network-device redirection escaped contact classification",
    )
    require(
        not contains_runtime_command(
            'printf %s "$EVIDENCE" > "$RUNNER_TEMP/release-intent.json"'
        ),
        "approved runner-temporary redirect was treated as runtime contact",
    )
    for unapproved_command in (
        "openssl s_client -connect runtime.example:443 </dev/null",
        (
            "export GITHUB_OUTPUT=/dev/tcp/runtime.example/443; "
            'printf x > "$GITHUB_OUTPUT"'
        ),
    ):
        unapproved_shell_contact = f"""name: synthetic
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - shell: bash
        run: {unapproved_command}
"""
        require(
            workflow_has_runtime_command(
                unapproved_shell_contact,
                "synthetic-release-intent-unapproved-shell-contact.yml",
            ),
            f"unapproved executable or redirect escaped contact classification: {unapproved_command}",
        )
    reusable_mutation = """name: synthetic
jobs:
  deploy:
    uses: vendor/runtime/.github/workflows/deploy.yml@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(reusable_mutation, "synthetic-reusable.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: reusable workflow mutation")
    local_reusable = ROOT / ".github/workflows/.codestra-local-runtime-negative.yml"
    try:
        local_reusable.write_text(
            """name: synthetic local runtime
on: workflow_call
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
""",
            encoding="utf-8",
        )
        caller = """name: synthetic caller
jobs:
  deploy:
    uses: ./.github/workflows/.codestra-local-runtime-negative.yml
"""
        try:
            require_mutating_jobs_disabled(caller, "synthetic-local-reusable.yml")
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: local reusable workflow mutation"
            )
    finally:
        local_reusable.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix=".codestra-contract-", dir=ROOT) as directory:
        local_script = Path(directory) / "runtime.sh"
        local_script.write_text("kubectl apply -f runtime.yml\n", encoding="utf-8")
        relative = local_script.relative_to(ROOT).as_posix()
        require(
            contains_runtime_mutation(f"bash {relative}"),
            "negative local interpreter script regression passed",
        )
        require(
            contains_runtime_mutation(relative),
            "negative directly invoked script regression passed",
        )
        require(
            contains_runtime_mutation(f"source {relative}"),
            "negative sourced script regression passed",
        )
        require(
            contains_runtime_mutation(f"$GITHUB_WORKSPACE/{relative}"),
            "negative workspace-qualified script regression passed",
        )
        working_directory = Path(directory) / "nested"
        working_directory.mkdir()
        nested_script = working_directory / "runtime-nested.sh"
        nested_script.write_text("docker service update runtime\n", encoding="utf-8")
        nested_relative = working_directory.relative_to(ROOT).as_posix()
        working_directory_workflow = f"""name: synthetic working directory
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - working-directory: {nested_relative}
        run: bash runtime-nested.sh
"""
        try:
            require_mutating_jobs_disabled(
                working_directory_workflow,
                "synthetic-working-directory.yml",
            )
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: working-directory script"
            )
        require(
            contains_runtime_mutation(
                "bash runtime-*.sh",
                working_directory=working_directory,
            ),
            "negative globbed script regression passed",
        )
        module_directory = working_directory / "ops"
        module_directory.mkdir()
        (module_directory / "__init__.py").write_text("", encoding="utf-8")
        (module_directory / "deploy.py").write_text(
            "import requests\n"
            "def deploy():\n"
            "    requests.post('https://runtime.example/deploy', data=b'x')\n",
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "python3 -m ops.deploy",
                working_directory=working_directory,
            ),
            "negative Python module regression passed",
        )
        require(
            contains_runtime_mutation(
                "python3 -B -E -I -s -m ops.deploy",
                working_directory=working_directory,
            ),
            "negative long-option Python module regression passed",
        )
        (working_directory / "wrapper.py").write_text(
            "from ops import deploy\n"
            "deploy.deploy()\n",
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "python3 wrapper.py",
                working_directory=working_directory,
            ),
            "negative imported local Python module regression passed",
        )
        (working_directory / "mutate.mjs").write_text(
            "fetch('https://runtime.example', {method: 'POST', body: 'x'})\n",
            encoding="utf-8",
        )
        (working_directory / "entry.mjs").write_text(
            "import './mutate.mjs'\n",
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "node entry.mjs",
                working_directory=working_directory,
            ),
            "negative local JavaScript import regression passed",
        )
        (working_directory / "malicious_test.py").write_text(
            "import subprocess\n"
            "subprocess.run(['kubectl', 'apply', '-f', 'runtime.yml'])\n",
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "python3 -m unittest malicious_test",
                working_directory=working_directory,
            ),
            "negative unittest target regression passed",
        )
        discovery_directory = working_directory / "discovery_tests"
        discovery_directory.mkdir()
        (discovery_directory / "test_runtime.py").write_text(
            "import subprocess\n"
            "subprocess.run(['kubectl', 'apply', '-f', 'runtime.yml'])\n",
            encoding="utf-8",
        )
        for invocation in (
            "python3 -m pytest",
            "python3 -m pytest discovery_tests",
            "python3 -m unittest",
            "python3 -m unittest discover -s discovery_tests",
        ):
            require(
                contains_runtime_mutation(
                    invocation,
                    working_directory=working_directory,
                ),
                f"negative test discovery regression passed: {invocation}",
            )
        (working_directory / "package.json").write_text(
            json.dumps(
                {
                    "name": "codestra-contract-fixture",
                    "scripts": {
                        "deploy": "kubectl apply -f runtime.yml",
                        "prepack": "kubectl apply -f runtime.yml",
                        "validate": "python3 -m compileall -q .",
                    }
                }
            ),
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "npm run deploy",
                working_directory=working_directory,
            ),
            "negative package script regression passed",
        )
        require(
            not contains_runtime_mutation(
                "npm run validate",
                working_directory=working_directory,
            ),
            "read-only package script regression failed",
        )
        require(
            contains_runtime_mutation(
                "npm pack",
                working_directory=working_directory,
            ),
            "negative package lifecycle regression passed",
        )
        require(
            contains_runtime_mutation(
                "npm --prefix . run deploy",
                working_directory=working_directory,
            ),
            "negative package option regression passed",
        )
        for scoped_command in (
            "npm --workspace codestra-contract-fixture run deploy",
            "pnpm --filter codestra-contract-fixture deploy",
        ):
            require(
                contains_runtime_mutation(
                    scoped_command,
                    working_directory=ROOT,
                ),
                "negative scoped package regression passed",
            )
    require(
        contains_runtime_mutation("bash generated-runtime.sh"),
        "negative unresolved script regression passed",
    )
    require(
        contains_runtime_mutation(
            "script -q -c 'kubectl apply -f runtime.yml' /dev/null"
        ),
        "negative command-executing script wrapper regression passed",
    )
    require(
        contains_runtime_mutation(
            "(echo harmless); kubectl apply -f runtime.yml"
        ),
        "negative coalesced shell separator regression passed",
    )
    require(
        contains_runtime_mutation(
            """python3 - <<'PY'
import subprocess
subprocess.run(["kubectl", "apply", "-f", "runtime.yml"], check=True)
PY
"""
        ),
        "negative stdin interpreter regression passed",
    )
    require(
        contains_runtime_mutation(
            """python3 <<'PY' > /tmp/out
import urllib.request
urllib.request.urlopen('https://runtime.example/mutate', data=b'x')
PY
"""
        ),
        "negative redirected heredoc regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            'import requests\nrequests.post("https://runtime.example/mutate")\n'
        ),
        "negative Python HTTP mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import requests\n"
            "class Holder: pass\n"
            "holder = Holder()\n"
            "holder.writer = requests.post\n"
            "holder.writer('https://runtime.example/mutate')\n"
        ),
        "negative attribute-stored HTTP writer regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import urllib.request\n"
            "request = urllib.request.Request("
            "'https://runtime.example/mutate', method='POST')\n"
        ),
        "negative Python urllib mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import urllib.request\n"
            "urllib.request.urlopen("
            "'https://runtime.example/mutate', data=b'x=1')\n"
        ),
        "negative Python urlopen body regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import urllib.request\n"
            "send = lambda *args, **kwargs: "
            "urllib.request.urlopen(*args, **kwargs)\n"
            "send(url, data=b'x')\n"
        ),
        "negative forwarded Python urlopen regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os, urllib.request\n"
            "urllib.request.Request('https://runtime.example/mutate', "
            "method=os.environ['METHOD'])\n"
        ),
        "negative computed urllib method regression passed",
    )
    for dynamic_import in (
        "__import__('subprocess').run(['kubectl', 'apply'])\n",
        "import importlib\n"
        "importlib.import_module('subprocess').run(['kubectl', 'apply'])\n",
    ):
        require(
            python_source_has_runtime_mutation(dynamic_import),
            "negative dynamic Python import regression passed",
        )
    require(
        python_source_has_runtime_mutation(
            "import boto3\nboto3.client('s3').upload_file('a', 'bucket', 'key')\n"
        ),
        "negative Python cloud-client mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import smtplib\nsmtp = smtplib.SMTP('smtp.example')\n"
            "smtp.sendmail('from@example', ['to@example'], 'message')\n"
        ),
        "negative live SMTP delivery regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.execvp('kubectl', ['kubectl', 'apply', '-f', 'runtime.yml'])\n"
        ),
        "negative Python os.exec mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.spawnlp(os.P_WAIT, 'kubectl', 'kubectl', 'apply', "
            "'-f', 'runtime.yml')\n"
        ),
        "negative Python os.spawn mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.posix_spawnp('kubectl', "
            "['kubectl', 'apply', '-f', 'runtime.yml'], os.environ)\n"
        ),
        "negative Python os.posix_spawn mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import asyncio\nasyncio.run(asyncio.create_subprocess_exec("
            "'kubectl', 'apply'))\n"
        ),
        "negative Python asyncio subprocess regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\n"
            "subprocess.__dict__['run'](['kubectl', 'apply'])\n"
        ),
        "negative subscripted Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch = subprocess.run\n"
            "launch(['kubectl', 'apply', '-f', 'runtime.yml'], check=True)\n"
        ),
        "negative assigned Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nclass Holder: pass\nholder = Holder()\n"
            "holder.runner = subprocess.run\n"
            "holder.runner(['kubectl', 'apply', '-f', 'runtime.yml'])\n"
        ),
        "negative attribute-bound Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\ndef invoke(runner):\n"
            "    runner(['kubectl', 'apply'])\ninvoke(subprocess.run)\n"
        ),
        "negative forwarded Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch: object = subprocess.run\n"
            "launch(['kubectl', 'apply', '-f', 'runtime.yml'], check=True)\n"
        ),
        "negative annotated Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch = subprocess.run\n"
            "launch(['kubectl', 'apply'])\nlaunch = print\n"
        ),
        "negative reassigned Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import requests\nrequests.Session().post('https://runtime.example/mutate')\n"
        ),
        "negative constructed Python client regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import http.client\n"
            "connection = http.client.HTTPConnection('runtime.example')\n"
            "connection.putrequest('POST', '/mutate')\n"
            "connection.endheaders(b'payload')\n"
        ),
        "negative low-level HTTP writer regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import requests\nclient = requests.Session()\n"
            "client.post('https://runtime.example/mutate')\n"
        ),
        "negative assigned Python client regression passed",
    )
    require(
        javascript_source_has_runtime_mutation(
            "await client.post('https://runtime.example/mutate')\n"
        ),
        "negative JavaScript HTTP mutation regression passed",
    )
    require(
        javascript_source_has_runtime_mutation(
            "await axios.request({method: 'post', url: '/mutate'})\n"
        ),
        "negative JavaScript generic request regression passed",
    )
    for javascript_mutation in (
        "const writer = axios.create(); await writer.post('/mutate')\n",
        "import transport from 'axios'; await transport.post('/mutate')\n",
        "const write = fetch; await write('/mutate', {method: 'POST'})\n",
        "await fetch(new URL(endpoint), {method: 'POST', body})\n",
        "const options = {method: 'POST', body: data}; fetch(url, options)\n",
        "const options = {method: 'POST', body: data}; "
        "fetch(url, {...options})\n",
        "import https from 'node:https'; "
        "https.request({method: 'POST'}, callback).end()\n",
        "const transport = await import/*comment*/('node:' + 'https'); "
        "transport.request(url, {method: 'POST'}).end(data)\n",
        "const transport = await import // line comment\n"
        "('node:' + 'https'); "
        "transport.request(url, {method: 'POST'}).end(data)\n",
        "const transport = await import // line comment\n"
        "('node:https'); "
        "transport.request({method: 'POST'}).end(data)\n",
        "const transport = await import"
        + "/* adjacent loader comment */" * 128
        + "('node:' + 'https'); "
        "transport.request(url, {method: 'POST'}).end(data)\n",
        "const ws = new WebSocket(url); "
        "ws.addEventListener('open', () => ws.send(payload))\n",
        'const {exec: run} = require("node:child_process"); '
        'run("kubectl apply -f runtime.yml")\n',
        "const cp = require('\\x63hild_process'); "
        "cp.execSync('kubectl apply -f runtime.yml')\n",
        "const cp = require.call(null, 'child_' + 'process');\n",
        "const cp = require.apply(null, ['child_' + 'process']);\n",
        "fetch(...args)\n",
        "process.getBuiltinModule('child_process').exec('kubectl apply')\n",
    ):
        require(
            javascript_source_has_runtime_mutation(javascript_mutation),
            "negative aliased/nested JavaScript mutation regression passed",
        )
    require(
        not python_source_has_runtime_mutation(
            'import requests\nrequests.get("https://evidence.example/status")\n'
        ),
        "read-only Python HTTP regression failed",
    )
    require(
        not python_source_has_runtime_mutation(
            'cursor.execute("SELECT status FROM evidence")\n'
        ),
        "read-only Python SQL regression failed",
    )
    require(
        python_source_has_runtime_mutation(
            'cursor.execute("WITH removed AS (DELETE FROM sessions RETURNING *) "'
            '"SELECT * FROM removed")\n'
        ),
        "negative mutating SQL CTE regression passed",
    )
    unsafe_validator = """import subprocess
subprocess.run([\"kubectl\", \"apply\", \"-f\", \"runtime.yml\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: runtime validator operation")
    unsafe_aliased_validator = """import subprocess as sp
sp.run(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_aliased_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: aliased runtime operation")
    unsafe_callable_validator = """import subprocess
runner = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: assigned subprocess callable"
        )
    unsafe_chained_callable_validator = """import subprocess
runner = subprocess.run.__call__
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_chained_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: chained subprocess callable"
        )
    for returned in ("(subprocess.run,)[0]", "{'runner': subprocess.run}['runner']"):
        unsafe = f"import subprocess\ndef helper():\n    return {returned}\nrunner = helper()\nrunner(['kubectl', 'apply'])\n"
        try:
            validate_release_validator_operations(unsafe)
        except ContractError:
            pass
        else:
            raise ContractError("container-returned restricted callable admitted")
    for options in (
        "{headers: {method: 'GET'}, method: 'POST'}",
        "{method: 'GET', method: 'POST'}",
        "{'method': 'POST'}",
    ):
        require(
            javascript_source_has_runtime_mutation(f"fetch(url, {options})"),
            "effective fetch mutation method admitted",
        )
    unsafe_annotated_callable_validator = """import subprocess
runner: object = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_annotated_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: annotated subprocess callable"
        )
    unsafe_chained_callable_validator = """import subprocess
ignored = runner = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_chained_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: chained subprocess callable"
        )
    for indirect_callable_validator in (
        "import subprocess\n(runner,) = (subprocess.run,)\n"
        "runner(['kubectl', 'apply'])\n",
        "import subprocess\ndef launcher():\n    return subprocess.run\n"
        "runner = launcher()\nrunner(['kubectl', 'apply'])\n",
        "import subprocess\nrunner = {'go': subprocess.run}['go']\n"
        "runner(['kubectl', 'apply'])\n",
        "import subprocess\nclass Holder: pass\nholder = Holder()\n"
        "holder.runner = subprocess.run\n"
        "holder.runner(['kubectl', 'apply'])\n",
        "import subprocess\nrunner = subprocess\n"
        "runner.run(['kubectl', 'apply'])\n",
        "import subprocess\ndef invoke(runner):\n"
        "    runner(['kubectl', 'apply'])\ninvoke(subprocess.run)\n",
        "import subprocess\ndef invoke(runner=subprocess.run):\n"
        "    runner(['kubectl', 'apply'])\ninvoke()\n",
        "import subprocess\nglobals()['runner'] = subprocess.run\n"
        "runner(['kubectl', 'apply'])\n",
    ):
        try:
            validate_release_validator_operations(indirect_callable_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: indirect restricted callable"
            )
    for unresolved_callable_validator in (
        "import subprocess\nsubprocess.__dict__['run'](['kubectl', 'apply'])\n",
        "import subprocess\n"
        "(runner := subprocess.run)(['kubectl', 'apply'])\n",
        "import asyncio\nasyncio.run(asyncio.create_subprocess_exec("
        "'kubectl', 'apply'))\n",
        "import os, multiprocessing\n"
        "multiprocessing.Process(target=os.system, args=('kubectl apply',)).start()\n",
    ):
        try:
            validate_release_validator_operations(unresolved_callable_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: unresolved callable"
            )
    for unsafe_dynamic_validator in (
        "import subprocess\nrunner = getattr(subprocess, 'run')\n"
        "runner(['kubectl', 'apply'])\n",
        "import urllib.request\ngetattr(urllib.request, 'urlopen')"
        "('https://runtime.example/mutate')\n",
        "import builtins\nbuiltins.exec("
        '"import os; os.system(\\\'kubectl apply -f runtime.yml\\\')")\n',
        "import builtins, subprocess\n"
        "launch = builtins.getattr(subprocess, 'run')\n"
        "launch(['kubectl', 'apply'])\n",
        "import importlib\n"
        "importlib.import_module('subprocess').run(['kubectl', 'apply'])\n",
    ):
        try:
            validate_release_validator_operations(unsafe_dynamic_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: dynamic restricted callable"
            )
    unsafe_mutated_command_validator = """import subprocess
command = ["git", "status"]
command[0] = "kubectl"
command[1] = "apply"
subprocess.run(command, check=True)
"""
    try:
        validate_release_validator_operations(unsafe_mutated_command_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: mutated allowlisted command"
        )
    unsafe_rebound_command_validator = """import os, subprocess
command = ["git", "status", "--porcelain"]
command = os.environ["COMMAND"].split()
subprocess.run(command, check=True)
"""
    try:
        validate_release_validator_operations(unsafe_rebound_command_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: rebound allowlisted command"
        )
    unsafe_method_mutated_command_validator = """import subprocess
command = ["git", "status"]
command.clear()
command.extend(["kubectl", "apply"])
subprocess.run(command, check=True)
"""
    try:
        validate_release_validator_operations(
            unsafe_method_mutated_command_validator
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: method-mutated allowlisted command"
        )
    for unsafe_os_validator in (
        "import os\nos.execvp('kubectl', ['kubectl', 'apply'])\n",
        "import os\nlaunch = os.posix_spawnp\n"
        "launch('kubectl', ['kubectl', 'apply'], os.environ)\n",
    ):
        try:
            validate_release_validator_operations(unsafe_os_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: release-validator OS launcher"
            )
    unsafe_urlopen = """import urllib.request
urllib.request.urlopen("https://runtime.example/mutate")
"""
    try:
        validate_release_validator_operations(unsafe_urlopen)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: unapproved URL opener")
    unsafe_aliased_urlopen = """import urllib.request
open_url = urllib.request.urlopen
open_url("https://runtime.example/mutate")
"""
    try:
        validate_release_validator_operations(unsafe_aliased_urlopen)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: aliased URL opener"
        )
    for unsafe_opener in (
        "import urllib.request\n"
        "urllib.request.build_opener().open(url, b'payload')\n",
        "import http.client\n"
        "http.client.HTTPSConnection(host).request('POST', path, body=data)\n",
        "import urllib.request\n"
        "class MutatingRequest(urllib.request.Request):\n"
        "    def get_method(self): return 'POST'\n",
    ):
        try:
            validate_release_validator_operations(unsafe_opener)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: unresolved network client"
            )
    for function_name in ("api_request", "download_artifact_archive"):
        for request_arguments in (
            "url, method='POST'", "url, data=b'payload'",
            "url, method=method", "url, **options", "url, b'payload'",
            "*arguments", "url, method='GET', data=b'payload'",
        ):
            unsafe = (
                "import urllib.request\n"
                f"def {function_name}():\n"
                f"    request = urllib.request.Request({request_arguments})\n"
            )
            try:
                validate_release_validator_operations(unsafe)
            except ContractError:
                pass
            else:
                raise ContractError(f"mutating evidence request admitted: {request_arguments}")
        for suffix in ("", ", method='GET'", ", method='HEAD'", ", data=None"):
            validate_release_validator_operations(
                "import urllib.request\n"
                f"def {function_name}():\n"
                f"    request = urllib.request.Request(url{suffix})\n"
            )
        for statement in (
            "NO_REDIRECT_OPENER.open(request, data=b'payload')",
            "NO_REDIRECT_OPENER.open(request, b'payload')",
            "NO_REDIRECT_OPENER.open(request, **options)",
            "request.method = 'POST'", "request.data = b'payload'",
            "request.full_url = 'https://runtime.example/mutate'",
            "request.host = 'runtime.example'",
            "request.selector = '/mutate'",
            "request.method: str = 'POST'",
            "request.__dict__['method'] = 'POST'",
            "request.__dict__['data'] = b'payload'",
            "object.__setattr__(request, 'method', 'POST')",
            "request.__setattr__('method', 'POST')",
            "request.__setattr__('data', b'payload')",
            "request.__setitem__('method', 'POST')",
        ):
            unsafe = (
                "import urllib.request\n"
                "NO_REDIRECT_OPENER = urllib.request.build_opener()\n"
                f"def {function_name}():\n"
                "    request = urllib.request.Request(url)\n"
                f"    {statement}\n"
            )
            try:
                validate_release_validator_operations(unsafe)
            except ContractError:
                pass
            else:
                raise ContractError(f"mutating evidence opener admitted: {statement}")
        unsafe_helper = (
            "import urllib.request\n"
            "NO_REDIRECT_OPENER = urllib.request.build_opener()\n"
            "def mutate(request):\n"
            "    request.method = 'POST'\n"
            f"def {function_name}():\n"
            "    request = urllib.request.Request(url)\n"
            "    mutate(request)\n"
            "    NO_REDIRECT_OPENER.open(request)\n"
        )
        try:
            validate_release_validator_operations(unsafe_helper)
        except ContractError:
            pass
        else:
            raise ContractError("helper-based request mutation admitted")
    unsafe_dynamic_registry = """import os, subprocess
subprocess.run(
    ["docker", "login", os.environ["RUNTIME_HOST"]],
    input=os.environ["GH_TOKEN"],
)
"""
    try:
        validate_release_validator_operations(unsafe_dynamic_registry)
    except ContractError:
        pass
    else:
        raise ContractError("dynamic evidence registry endpoint admitted")
    unsafe_path_shadow = """import os, subprocess
from pathlib import Path
Path("docker").write_text("#!/bin/sh\\nkubectl apply -f runtime.yml\\n")
Path("docker").chmod(0o755)
os.environ["PATH"] = ".:" + os.environ["PATH"]
subprocess.run(["docker", "login", "ghcr.io", "--username", "test"])
"""
    try:
        validate_release_validator_operations(unsafe_path_shadow)
    except ContractError:
        pass
    else:
        raise ContractError("mutable executable search path admitted")
    unsafe_bytes_path_shadow = """import os, subprocess
from pathlib import Path
Path("docker").write_text("#!/bin/sh\\nkubectl apply -f runtime.yml\\n")
Path("docker").chmod(0o755)
os.environb[b"PATH"] = b".:" + os.environb[b"PATH"]
subprocess.run(["docker", "login", "ghcr.io", "--username", "test"])
"""
    try:
        validate_release_validator_operations(unsafe_bytes_path_shadow)
    except ContractError:
        pass
    else:
        raise ContractError("mutable byte executable search path admitted")
    for source in (
        'import transport from "axios"; transport.post(runtimeUrl, payload)',
        'import { request as send } from "undici"; send(url, options)',
        'import * as transport from "node:https"; transport.request(options)',
        'const transport = require("axios"); transport.create().post(url, body)',
        'const {default: transport} = await import("got"); transport.post(url)',
        'import transport from "axios/dist/node/axios.cjs"; transport.post(url)',
        "const transport = await import('node:' + 'https'); "
        "transport.request(url, {method: 'POST'}).end(data)",
    ):
        require(javascript_source_has_runtime_mutation(source),
                f"imported network alias bypass admitted: {source}")
    require(not javascript_source_has_runtime_mutation(
        'import { strict as assert } from "node:assert"; assert.equal(1, 1)'
    ), "read-only non-network import was rejected")
    for smtp_source in (
        "import smtplib; smtp = smtplib.SMTP('example.invalid'); "
        "smtp.sendmail('a', 'b', 'c')",
        "from smtplib import SMTP_SSL as Mail; "
        "Mail('example.invalid').send_message(message)",
        "import aiosmtplib; aiosmtplib.send(message)",
        "import socket; socket.socket().sendto(b'payload', ('runtime.example', 9))",
        "import socket; socket.socket().makefile('wb').write(b'payload')",
        "import socket; socket.socket().sendmsg([b'payload'])",
        "import socket; socket.socket().sendfile(open('payload.bin', 'rb'))",
        "import requests; (session := requests.Session()).post(url, data=b'x')",
        "import os; os.system.__call__('kubectl apply -f runtime.yml')",
    ):
        require(
            python_source_has_runtime_mutation(smtp_source),
            "negative SMTP delivery regression passed",
        )
    unsafe_status_writer = """import subprocess
subprocess.run([\"gh\", \"api\", \"--method\", \"POST\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_status_writer)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: validator status writer")
    unsafe_buildx_writer = """import subprocess
subprocess.run(["docker", "buildx", "build", "--push", "."], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_buildx_writer)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: validator image writer")
    require(
        not contains_runtime_command(
            'gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch'
        ),
        "fixed GitHub control-plane read was treated as runtime contact",
    )
    for command in (
        'gh api --hostname runtime.example "repos/${GITHUB_REPOSITORY}" --jq .default_branch',
        "gh api https://runtime.example/status --jq .status",
        'GH_HOST=runtime.example gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch',
    ):
        require(
            contains_runtime_command(command),
            f"unapproved GitHub API authority escaped: {command}",
        )
    for command in (
        "curl -X POST https://runtime.example/mutate",
        "METHOD=POST; curl -X \"$METHOD\" https://runtime.example/mutate",
        "curl --data-urlencode action=deploy https://runtime.example/mutate",
        "gh api --method POST repos/example/runtime/dispatches",
        "gh -R example/runtime workflow run deploy.yml",
        "gh run rerun 123 -R example/runtime",
        "gh issue create --title incident --body mutation",
        "gh pr merge 123",
        "gh release create v1 artifact.tar.gz",
        "git -c alias.deploy='!kubectl apply -f runtime.yml' deploy",
        "git push origin HEAD:main",
        "awk 'BEGIN { system(\"kubectl apply -f runtime.yml\") }'",
        "watch -n 60 kubectl apply -f runtime.yml",
        "bash -c \"$(printf 'kubectl apply -f runtime.yml')\"",
        "aws ecs update-service --cluster production --service api",
        "aws s3 cp artifact s3://production-bucket/artifact",
        "env -i kubectl apply -f runtime.yml",
        "sudo -n ssh runtime.example deploy",
        "sudo --unknown-option harmless-command",
        "systemd-run --wait kubectl apply -f runtime.yml",
        "printf 'POST /mutate' | nc runtime.example 80",
        "printf 'POST /mutate' | openssl s_client -connect runtime.example:443",
        "cat <(printf x)\nkubectl apply -f runtime.yml",
        "kubectl auth reconcile -f runtime-role.yml",
        "docker stack deploy -c compose.yml app",
        "docker service update --image example.invalid/app service",
        "docker run --rm bitnami/kubectl apply -f runtime.yml",
        "builtin eval 'kubectl apply -f runtime.yml'",
        "timeout 60 kubectl apply -f runtime.yml",
        "result=`kubectl apply -f runtime.yml`",
        'result="$(kubectl apply -f runtime.yml)"',
        'tool=kubectl; "$tool" apply -f runtime.yml',
        'TOOL=$(echo kubectl); "$TOOL" apply -f runtime.yml',
        'tool=kubectl; "$tool" apply -f runtime.yml; tool=echo',
        'tool=kubectl; echo tool=echo; "$tool" apply -f runtime.yml',
        'kubectl "$ACTION" -f runtime.yml',
        "coproc kubectl apply -f runtime.yml",
        "deploy() { kubectl apply -f runtime.yml; }; deploy",
        "printf '%s ' runtime.yml | xargs kubectl apply -f",
        "printf kubectl | xargs --replace={} {} apply -f runtime.yml",
        "printf kubectl | xargs $(printf '%s' '--replace={}') "
        "sh -c '{} apply -f runtime.yml'",
        "printf '%s\\0' 'kubectl apply -f runtime.yml' | xargs -0 sh -c",
        "printf './deploy.sh\\n' | xargs bash",
        "echo validation\n\ngh api --method POST repos/example/runtime/dispatches",
        "ionice kubectl apply -f runtime.yml",
        "sudo chroot / kubectl apply -f runtime.yml",
        "GIT_ALLOW_PROTOCOL=ext git fetch ext::sh\\ -c\\ id",
        "trap 'kubectl apply -f runtime.yml' EXIT",
        "find . -exec kubectl apply -f runtime.yml {} \\;",
        'ACTION=-exec; find . "$ACTION" kubectl apply -f runtime.yml {} \\;',
        'find . "${ACTION}" kubectl apply -f runtime.yml {} \\;',
        'action=-execdir; find . "$action" sh -c '
        '"kubectl apply -f runtime.yml" \\;',
        "shopt -s expand_aliases; alias deploy='kubectl apply -f runtime.yml'; deploy",
        "make up",
        "curl -K request.conf",
        "curl -fsSL https://example.invalid/deploy.sh | bash",
        "python3 -c \"import subprocess; "
        "subprocess.run(['kubectl', 'apply', '-f', 'runtime.yml'])\"",
        "python3 -B -E -I -c \"import subprocess; "
        "subprocess.run(['kubectl', 'apply'])\"",
        "node --eval='require(\"node:child_process\").execSync("
        '"kubectl apply -f runtime.yml")\'',
        "python3 -c'import os; os.system(\"kubectl apply -f runtime.yml\")'",
        "/tmp/python",
        "/tmp/generated-runtime apply",
        "echo foo\\ # `kubectl apply -f runtime.yml`",
    ):
        require(
            contains_runtime_mutation(command),
            f"negative API mutation regression passed: {command}",
        )
    for run in (
        "docker buildx build --push -t ghcr.io/example/image .",
        "docker buildx build --output=type=registry,name=ghcr.io/example/image .",
        "docker buildx build -o type=image,name=ghcr.io/example/image,push=true .",
        "docker buildx bake --push",
        "docker buildx imagetools create --tag ghcr.io/example/image:release source@sha256:deadbeef",
        "publish() { docker \"$@\"; }\npublish push ghcr.io/example/image:release",
    ):
        require(
            contains_image_publication({"run": run}),
            f"negative shell image publication regression passed: {run}",
        )
    require(
        not contains_runtime_mutation(
            "find . -type f -print0 | xargs -0 sha256sum"
        ),
        "read-only xargs checksum regression failed",
    )
    require(
        not contains_runtime_mutation("# `kubectl apply -f runtime.yml`"),
        "comment-only legacy substitution was treated as executable",
    )


# Narrow, explicit, hash-pinned exemptions for reviewed jobs whose detected
# mutations are bounded by their permissions and exact job bodies. The jobs
# remain counted as mutating; only the two global disable requirements are
# skipped when the repository/path/job content matches an approved hash.
APPROVED_NARROW_MUTATION_SHA256: dict[str, dict[str, str]] = {
    "ingtrader21-spec/Middleware-": {
        # Read-only release verification writes only runner-local evidence and
        # job outputs. Its workflow grants actions:read and contents:read only.
        ".github/workflows/automated-production-promotion.yml:verify-release": (
            "d95747c8989fcdf847f52cbc1cd2f5f7"
            "d53e18c3f4772736f51038351e41d0c0"
        ),
        # The only external mutation is the required job posting its own exact
        # commit status through checks:write.
        ".github/workflows/required-ci.yml:test": (
            "4c1335859514a384a7e7b9667250821b"
            "8ee7d0bbf9d34e3968d40174d9dd4f3b"
        ),
        # The single forward Middleware production publisher: builds, scans,
        # signs and verifies one immutable image from the exact protected-main
        # source after Middleware CI succeeded. Only these exact job bytes are
        # authorized; any edit to the job needs a new trust generation.
        ".github/workflows/release.yml:release": (
            "f27b3be9bdca2bb96ed171a4f23ed6842f01a27c6f4d85508afea3fe1f63c2db"
        ),
    },
}


def require_mutating_jobs_disabled(workflow: str, path: str) -> None:
    mutating_jobs = 0
    script_aliases = workflow_script_aliases(workflow, path)
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_control_plane = (
        APPROVED_CONTROL_PLANE_WORKFLOW_SHA256.get(repository, {}).get(path)
        == hashlib.sha256(workflow.encode()).hexdigest()
    )
    approved_job_configuration = job_executable_configuration_approved(
        workflow,
        path,
    )
    for job_name, job in workflow_jobs(workflow, path).items():
        # Publishing a registry image is a runtime mutation in every repository
        # without runtime-mutation authority, whatever the shell that does it.
        publishes = any(
            contains_image_publication(step) for step in workflow_steps(job, path)
        )
        if approved_control_plane:
            mutating = publishes or job_reusable_workflow_mutation(job, path) or any(
                script_dependencies_have_runtime_mutation(
                    str(step.get("run", "")),
                    script_aliases,
                    step_working_directory(job, step, path),
                )
                or isinstance(step.get("uses"), str)
                and str(step["uses"]).strip().startswith("./")
                for step in workflow_steps(job, path)
            )
        else:
            mutating = publishes or job_executable_configuration_mutation(
                job,
                approved=approved_job_configuration,
            ) or job_reusable_workflow_mutation(job, path) or any(
                step_has_runtime_mutation(job, step, path, script_aliases)
                or contains_runtime_action(step)
                for step in workflow_steps(job, path)
            )
        if mutating:
            mutating_jobs += 1
            approved_narrow_mutation = (
                APPROVED_NARROW_MUTATION_SHA256.get(repository, {}).get(
                    f"{path}:{job_name}"
                )
                == hashlib.sha256(job.raw.encode()).hexdigest()
            )
            if not approved_narrow_mutation:
                require(
                    "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                    f"mutating job lacks disable marker: {path}:{job_name}",
                )
                require(
                    job_condition(job) == "${{ false }}",
                    f"mutating job is not unconditionally disabled: {path}:{job_name}",
                )
    require(mutating_jobs > 0, f"native mutation classification drift: {path}")


def require_image_publishing_jobs_disabled(workflow: str, path: str) -> None:
    publishing_jobs = 0
    for job in workflow_jobs(workflow, path).values():
        if any(
            contains_image_publication(step)
            for step in workflow_steps(job, path)
        ):
            publishing_jobs += 1
            require(
                "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                f"image-publishing job lacks disable marker: {path}",
            )
            require(
                job_condition(job) == "${{ false }}",
                f"image-publishing job is not unconditionally disabled: {path}",
            )
    require(publishing_jobs > 0, f"image publication classification drift: {path}")



def validate_portfolio_control_plane_bindings() -> None:
    repository = "ingtrader21-spec/Middleware-"
    path = ".github/workflows/portfolio-production-ruleset-apply.yml"
    if not (ROOT / path).is_file():
        return
    workflow = (ROOT / path).read_text(encoding="utf-8")
    require(not workflow_has_runtime_mutation(workflow, path), "pinned portfolio governance was rejected")
    require(workflow_has_runtime_mutation(workflow + "\n# changed\n", path), "portfolio workflow drift was accepted")
    bindings = APPROVED_CONTROL_PLANE_DEPENDENCY_SHA256[repository][path]
    for dependency, expected in bindings.items():
        bindings[dependency] = "0" * 64
        try:
            require(
                workflow_has_runtime_mutation(workflow, path),
                f"portfolio dependency drift was accepted: {dependency}",
            )
        finally:
            bindings[dependency] = expected


def main() -> int:
    contract = load_contract()
    validate_portfolio_control_plane_bindings()
    validate(contract)
    validate_negative_regressions(contract)
    validate_intent_negative_regressions(contract)
    subprocess.run(
        ["python3", str(RELEASE_VALIDATOR_PATH), "--self-test"],
        cwd=ROOT,
        check=True,
    )
    expected_sha = os.environ.get("EXPECTED_SHA")
    if expected_sha:
        require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "expected source SHA is invalid")
        actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        require(actual_sha == expected_sha, "contract validation checkout is not the exact event source")
    print("PRODUCTION_ORCHESTRATOR_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
