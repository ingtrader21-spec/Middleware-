#!/usr/bin/env python3
"""Validate a normalized release intent without contacting any runtime."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from copy import deepcopy
from email.message import Message
from pathlib import Path
from typing import Any, cast


CONTRACT_PATH = Path(".codestra/production-orchestrator-contract.v1.json")
SCHEMA = "codestra.production-orchestrator-contract.v1"
WORKFLOW = ".github/workflows/manual-release-intent.yml"
CONTROLLER_REPOSITORY = "appolon1908-hue/codestra-production-platform"
CONTROLLER_BRANCH = "release/production-activation"
INDEPENDENT_REVIEWER_ID = 77101516
CANDIDATE_SCHEMA = "codestra.manual-production-candidate.v1"
ZERO64 = "0" * 64
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$")
IMAGE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")
IMAGE_REPOSITORY = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+$")
CONFIRMATIONS = {
    "plan": "PLAN_RELEASE_INTENT",
    "staging": "APPROVE_STAGING_INTENT",
    "canary": "APPROVE_CANARY_INTENT",
    "production": "APPROVE_PRODUCTION_INTENT",
}
PREVIOUS_PHASE = {"staging": "plan", "canary": "staging", "production": "canary"}
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
CANDIDATE_SAFETY_KEYS = (SAFETY_KEYS - {"external_effects_default"}) | {
    "external_effects_enabled"
}
CATALOG_REPOSITORIES = {
    "appolon1908-hue/Infustruction-repo",
    "appolon1908-hue/Keycloak",
    "ingtrader21-spec/Middleware-",
    "appolon1908-hue/codestra",
    "appolon1908-hue/beyvra-backend",
    "appolon1908-hue/backend2",
    "appolon1908-hue/beyvra-frontend",
    "appolon1908-hue/scrapper",
    "appolon1908-hue/Breero.com",
    "appolon1908-hue/Moneybee-Backend",
    "appolon1908-hue/Telnexa-web",
    CONTROLLER_REPOSITORY,
}
PR_ONLY_REQUIRED_CHECKS = {
    "appolon1908-hue/Keycloak": frozenset({"bootstrap"}),
    "ingtrader21-spec/Middleware-": frozenset(
        {
            "Validate middleware merge result",
            "Validate middleware source head",
        }
    ),
}
EXPECTED_CHECK_WORKFLOWS = {
    "appolon1908-hue/Infustruction-repo": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "validate": ".github/workflows/source-authority-matrix.yml",
        "validate-source": ".github/workflows/source-authority-matrix.yml",
        "validate-merge-result": ".github/workflows/source-authority-matrix.yml",
    },
    "appolon1908-hue/Keycloak": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "validate": ".github/workflows/validate.yml",
        "validate-source": ".github/workflows/validate.yml",
        "validate-merge-result": ".github/workflows/validate.yml",
    },
    "ingtrader21-spec/Middleware-": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "validate": ".github/workflows/middleware-ci.yml",
        "connector-runtime-build": ".github/workflows/middleware-ci.yml",
        "docker-test-build": ".github/workflows/middleware-ci.yml",
        "docker-runtime-build": ".github/workflows/middleware-ci.yml",
        "container-security": ".github/workflows/middleware-ci.yml",
        "Disposable PostgreSQL Redis integration": ".github/workflows/middleware-ci.yml",
        "Disposable NATS JetStream integration": ".github/workflows/middleware-ci.yml",
        "Temporal critical workflow integration": ".github/workflows/middleware-ci.yml",
        "Synthetic no-effect acceptance E2E": ".github/workflows/middleware-ci.yml",
    },
    "appolon1908-hue/codestra": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "verify": ".github/workflows/ci.yml",
        "container": ".github/workflows/ci.yml",
    },
    "appolon1908-hue/beyvra-backend": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "container": ".github/workflows/ci.yml",
        "exact-head-base-ci": ".github/workflows/ci.yml",
        "secrets": ".github/workflows/ci.yml",
        "validate": ".github/workflows/ci.yml",
    },
    "appolon1908-hue/backend2": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "validate": ".github/workflows/ci.yml",
        "container": ".github/workflows/ci.yml",
    },
    "appolon1908-hue/beyvra-frontend": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "exact-head-base-ci": ".github/workflows/ci.yml",
        "secrets": ".github/workflows/ci.yml",
        "validate": ".github/workflows/ci.yml",
    },
    "appolon1908-hue/scrapper": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "deployment-policy": ".github/workflows/ci.yml",
        "validate": ".github/workflows/ci.yml",
    },
    "appolon1908-hue/Breero.com": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "quality": ".github/workflows/quality.yml",
    },
    "appolon1908-hue/Moneybee-Backend": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "verify": ".github/workflows/ci.yml",
        "postgres-identity-tenancy": ".github/workflows/ci.yml",
        "containers (api)": ".github/workflows/ci.yml",
        "containers (worker)": ".github/workflows/ci.yml",
        "containers (migrate)": ".github/workflows/ci.yml",
        "application": ".github/workflows/secure-ci.yml",
        "deployment-policy": ".github/workflows/secure-ci.yml",
    },
    "appolon1908-hue/Telnexa-web": {
        "orchestrator-contract": ".github/workflows/production-orchestrator-contract.yml",
        "validate-build-smoke": ".github/workflows/ci.yml",
        "docker-build": ".github/workflows/ci.yml",
    },
    CONTROLLER_REPOSITORY: {
        "checks-only-policy": ".github/workflows/production-merge-gate.yml",
        "diagnose": ".github/workflows/gitleaks-pr-diagnostics.yml",
        "production-gate": ".github/workflows/production-merge-gate.yml",
        "validate": ".github/workflows/platform-source-gate.yml",
    },
}
ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = (
    "5e968a824d9738ac8237dfd677bae1091aaecfe73f3f98d0c6c63f07a503968f"
)
EXPECTED_CHECK_WORKFLOW_SHA256 = {
    "appolon1908-hue/Infustruction-repo": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/source-authority-matrix.yml": "1ca826d1f37c06b0ad2bc5a94a5b19516ad24fce486bdaa1b5b384e62f759221",
    },
    "appolon1908-hue/Keycloak": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/validate.yml": "34e8692d93f3a30949e1e3de0543d4db93c508ce026538f6b5a8442d1a800f1a",
    },
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/middleware-ci.yml": "8cec813feb267b63f4f27807606237dbe518f2fb94379062e447a6636fea2f16",
    },
    "appolon1908-hue/codestra": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "7b0a377343c86b1274ecb91c4cc2423d6c045c0197eae9eb1abe775d791a73d1",
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "1c2e654ffd1011f662985d261411502c392789b882b6d089ba18e182e53248d1",
    },
    "appolon1908-hue/backend2": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "e27367a06aa79f7adca93d148f7e9c88efe35e77a3893407ffc3988f1b36c217",
    },
    "appolon1908-hue/beyvra-frontend": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "7459a31c6b005e9345661b10ee8df45a570ac652280a2eacbcdfd4673fb115da",
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "31d81c5be094a1510bc821ef4359bba591630d2273662f5de0683205d908c60d",
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/quality.yml": "9e8367e853316594a325fbcb0f22f1e701c35c205b15e66a5228ae8b4ce10ce4",
    },
    "appolon1908-hue/Moneybee-Backend": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "0bed241476483a0ac38e0fc8bb2b06a23b076645a6b0b355cf0420fcf4d2f451",
        ".github/workflows/secure-ci.yml": "6ab4ebf30e47aee65ba3e1d7106ddd0c6feea546a57ebd289cf4fcfed9106e00",
    },
    "appolon1908-hue/Telnexa-web": {
        ".github/workflows/production-orchestrator-contract.yml": ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256,
        ".github/workflows/ci.yml": "1b8db51b1d607a04b9d1f578802c4f58d1eb824638cc5a9ac1bd114a9869a462",
    },
    CONTROLLER_REPOSITORY: {
        ".github/workflows/gitleaks-pr-diagnostics.yml": "2edfc97221b0fc0b8668075056b6205494eb77e37d037017fcfb2fa6d04ba732",
        ".github/workflows/platform-source-gate.yml": "e1de711a014a5056083aba8755289916b4a7fd6eadaf3ec2aa77077821c925ff",
        ".github/workflows/production-merge-gate.yml": "921eb777b8e6beb77a038b88edcc9a0b1ccba34d4e4cf8b68ce94768c4d5e47e",
    },
}
SHARED_PRODUCTION_VALIDATOR_SHA256 = (
    "6006bbc7850ce7666de926b6cad2585b"
    "83d2fce102104543b871530f11115f20"
)
KEYCLOAK_PRODUCTION_VALIDATOR_SHA256 = (
    "6006bbc7850ce7666de926b6cad2585b"
    "83d2fce102104543b871530f11115f20"
)
MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256 = (
    "15c35ad11c65b7605d44812e08d45493e31afdea678876b3a44a16d27c1c1a21"
)
BACKEND_PRODUCTION_VALIDATOR_SHA256 = (
    "6006bbc7850ce7666de926b6cad2585b"
    "83d2fce102104543b871530f11115f20"
)
EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256 = {
    "appolon1908-hue/Infustruction-repo": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/Keycloak": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": KEYCLOAK_PRODUCTION_VALIDATOR_SHA256,
        },
        ".github/workflows/validate.yml": {
            "Dockerfile": (
                "43c8c2347e91c23adffbeb01955b7bf3"
                "d0fce6c2b1e47b66f8eedc9a172ff86e"
            ),
            "compose.yaml": (
                "95f1f64a4383bcde88004363860adeb5"
                "16821e669ca0a473c5e11d5b803c6342"
            ),
            "scripts/test-plan-gate.sh": (
                "a1998a4a92a2535aea09f35c5de369f"
                "0675ab4276e86ab92a42f908590c0ca6d"
            ),
            "scripts/validate-governance.sh": (
                "cefd59aaba1446e9aa0d8b0fc5370eab"
                "90f1d629422a0be25fad675515440c80"
            ),
            "scripts/validate-service-integrations.py": (
                "8063ee5e69b6dd3da7682f56e76a8b9"
                "e92c1b0dab785a961b4e05372d9f9d132"
            ),
            "scripts/validate.sh": (
                "770f873d978b072dc86d5b8bec1c958f"
                "3a02d67b69bdda27f8cc77a3da6ee3d8"
            ),
        },
    },
    "ingtrader21-spec/Middleware-": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256,
        },
        ".github/workflows/middleware-ci.yml": {
            "Dockerfile.runtime": (
                "0ef6f547f538c625d5041d46848b58ebe"
            "255d1aa66dabb2bb564f6300d99c84a"
            ),
            "scripts/integration_ci.sh": (
                "8d9327fd9ad51d6ba7243d051336f623"
                "a4f75d60c60e69fd012e65f598b12d4a"
            ),
            "scripts/nats_integration_ci.sh": (
                "88d843c665cece68e0fb56a931c295ee"
                "10490446cad7b64d9f5356c1cbf7263d"
            ),
            "scripts/run_ci.sh": (
                "64d7c92279dd442144c7e1f74c3e48f"
                "0ab5d5db105238a534dcf8ccd99e93138"
            ),
            "scripts/synthetic_acceptance_ci.sh": (
                "087dac2c5371f2013fa0a8dd22ed4024"
                "409ab5015231fb8801c75cf3203e3a8a"
            ),
            "scripts/temporal_integration_ci.sh": (
                "76a682cc1f5b15a0a3eb15a029d87206"
                "238dfe4a262eaf5fa2c79403f147d4d6"
            ),
            "scripts/verify_container_image.sh": (
                "86550c26b32862fefaf2cefdefa2db1e"
            "73abcb702d28536816f9093df47c5ccd"
            ),
        },
    },
    "appolon1908-hue/codestra": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": BACKEND_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/backend2": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/beyvra-frontend": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
        ".github/workflows/quality.yml": {
            ".github/workflows/backend-production.yml": (
                "45b2918627995cb3491f55b3a3b537e"
                "4a34598d7b32877879b9e2c912c266591"
            ),
            ".github/workflows/frontend-production.yml": (
                "ba5f99dcdbcdb78e4e638153fb740ab1"
                "04502cb2f8c75923a134d7d5e1e24b8d"
            ),
            ".github/workflows/release-images.yml": (
                "edf3678604b134a21bc69ba8e793f0bc"
                "542dd4e0005d79e3e71eb2a112563b5b"
            ),
            "apps/api/Dockerfile": (
                "9f2a4ea8ee572d02a238bdeb6aa5dc4d"
                "c122fd348dea23e32e92f9cf94453fe5"
            ),
            "deploy/frontend/Dockerfile": (
                "0f6ee0e77e353b56660fe317826f2fb8"
                "6a2eb4391b55f93e816312eb0f588717"
            ),
            "deploy/portals/Dockerfile": (
                "8ec9b8ac30f114bd65e2b70558ca4125"
                "2049c9fc5458a3d758cc5766daad4b9b"
            ),
            "scripts/ci/classify-quality-scope.sh": "7cc6cc7d213e4c962a8cda4ce052bbcfa51decc1af78ac663b1170c1b8c210c2",
            "scripts/ci/test-classify-quality-scope.sh": "0365cd71d85e00facf1a64c2f11734e413430af75e4cf39e0e52971d13d5c473",
            "scripts/ci/test-validate-breero-scope.sh": "ea29de36868e28ff82e3ec151f896aed388d2421f5907151c4c13480dae20bf8",
            "scripts/ci/validate-breero-scope.sh": "f8ffb8a3953c56d7d6722938825bfb33fced802ba162f4cefd3d12be8ffb9a1e",
        },
    },
    "appolon1908-hue/Moneybee-Backend": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
    "appolon1908-hue/Telnexa-web": {
        ".github/workflows/production-orchestrator-contract.yml": {
            ".codestra/validate-production-orchestrator-contract.py": SHARED_PRODUCTION_VALIDATOR_SHA256,
        },
    },
}
RELEASE_VALIDATOR_SOURCE_PATH = ".codestra/validate-release-intent.py"
EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256 = {
    "appolon1908-hue/Infustruction-repo": (
        "218de46417be1425f8686cdf35c881ae"
        "cad750495cbe4576831de6aec3e642b2"
    ),
    "appolon1908-hue/Keycloak": (
        "0a409c1c9cc8c6f43d2d83d5347b9433"
        "fcdd0d5c3832479b10deda8c6a6afca6"
    ),
    "ingtrader21-spec/Middleware-": (
        "6cc0c444a2466f7e8647324be5f03cd906"
        "8124a80dfe693f51014a91b61523cd"
    ),
    "appolon1908-hue/codestra": (
        "4e3ea69c3ec2a4bd6e4b50395672f44d"
        "ec4a75460ed8648186445f1e8793b016"
    ),
    "appolon1908-hue/beyvra-backend": (
        "8a3a6eb731ece61cc83f8e0333689f70"
        "87be9db4f7e93698a37f860fdd453135"
    ),
    "appolon1908-hue/backend2": (
        "fa191e95756aec0a8987425eb697eb8e"
        "2316d7b59ba77e6cd10bb52b10c2c43a"
    ),
    "appolon1908-hue/beyvra-frontend": (
        "ce51e23c535871d23306264bb3806bb1"
        "3a710efeb649e0247e3377ac929ab5eb"
    ),
    "appolon1908-hue/scrapper": (
        "783feb31fc0ada4b043a62bf53dbfc1f"
        "19ad25962daeeff809b9a9d391b1e2f0"
    ),
    "appolon1908-hue/Breero.com": (
        "d59c04b6a621ab43c8e57c795880b050"
        "c27b77d05e43e4edb696db6aac677e60"
    ),
    "appolon1908-hue/Moneybee-Backend": (
        "a283e388028892ced3ac8445893ec2fa"
        "8bd7c7373418284f08106c82b765c31a"
    ),
    "appolon1908-hue/Telnexa-web": (
        "dbd17acc6862e74d9eb5ffbaf3a1f3f4"
        "9c41e364057a08e3aa57588afea236a3"
    ),
    CONTROLLER_REPOSITORY: (
        "4c7b54aa7cd59ac09703d235a264b830"
        "7c1757e4335a63a043b88d260b6d6a2b"
    ),
}


class PolicyError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


NO_REDIRECT_OPENER: Any = urllib.request.build_opener(NoRedirectHandler())


def api_request(
    endpoint: str,
    *,
    accept: str = "application/vnd.github+json",
    administration: bool = False,
) -> tuple[bytes, str | None]:
    url = endpoint if endpoint.startswith("https://") else f"https://api.github.com/{endpoint.lstrip('/')}"
    parsed = urllib.parse.urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname == "api.github.com", "refusing non-GitHub API URL")
    token_name = "CODESTRA_ORCHESTRATOR_TOKEN" if administration else "GH_TOKEN"
    token = os.environ.get(token_name, "")
    require(bool(token), f"{token_name} is required for repository policy evidence")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=30) as response:
            return response.read(), response.headers.get("Link")
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise PolicyError("unexpected redirect from GitHub API") from error
        raise


def validate_artifact_storage_url(location: str) -> str:
    parsed = urllib.parse.urlparse(location)
    hostname = parsed.hostname or ""
    allowed_host = (
        hostname.endswith(".blob.core.windows.net")
        or hostname.endswith(".actions.githubusercontent.com")
        or hostname in {"objects.githubusercontent.com", "github-releases.githubusercontent.com"}
    )
    require(
        parsed.scheme == "https"
        and allowed_host
        and parsed.username is None
        and parsed.password is None
        and parsed.port in (None, 443)
        and bool(parsed.path)
        and not parsed.fragment,
        "artifact redirect target is not an approved HTTPS storage URL",
    )
    return location


def download_artifact_archive(endpoint: str) -> bytes:
    url = endpoint if endpoint.startswith("https://") else f"https://api.github.com/{endpoint.lstrip('/')}"
    parsed = urllib.parse.urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname == "api.github.com", "refusing non-GitHub artifact API URL")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=30):
            raise PolicyError("artifact API did not redirect to signed storage")
    except urllib.error.HTTPError as error:
        if error.code not in {301, 302, 303, 307, 308}:
            raise
        location = error.headers.get("Location", "")
        error.close()
    storage_url = validate_artifact_storage_url(location)
    storage_request = urllib.request.Request(storage_url, headers={"Accept": "application/zip"})
    with NO_REDIRECT_OPENER.open(storage_request, timeout=30) as response:
        archive = response.read(10_000_001)
    require(len(archive) <= 10_000_000, "prior artifact archive exceeds size limit")
    return archive


def next_link(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(","):
        fields = [field.strip() for field in part.split(";")]
        if len(fields) >= 2 and 'rel="next"' in fields[1:]:
            require(fields[0].startswith("<") and fields[0].endswith(">"), "invalid pagination link")
            return fields[0][1:-1]
    return None


def api_json(endpoint: str, *, administration: bool = False) -> Any:
    raw, _ = api_request(endpoint, administration=administration)
    return json.loads(raw)


def api_pages(endpoint: str, *, administration: bool = False) -> list[Any]:
    pages: list[Any] = []
    seen: set[str] = set()
    current: str | None = endpoint
    while current is not None:
        require(current not in seen, "GitHub API pagination loop detected")
        seen.add(current)
        raw, link = api_request(current, administration=administration)
        pages.append(json.loads(raw))
        current = next_link(link)
    return pages


def bind_required_check(bindings: dict[str, int], name: object, app_id: object, expected_app_id: int) -> None:
    if not isinstance(name, str) or not name:
        raise PolicyError("invalid required check name")
    if not isinstance(app_id, int):
        raise PolicyError(f"required check {name} has no GitHub App binding")
    require(app_id == expected_app_id, f"required check {name} is not bound to the expected GitHub App")
    require(bindings.get(name) in (None, app_id), f"conflicting app bindings for required check {name}")
    bindings[name] = app_id


def required_check_bindings(branch: dict[str, Any], rules_pages: list[Any], expected_app_id: int) -> tuple[list[str], dict[str, int]]:
    policy = branch.get("protection", {}).get("required_status_checks", {})
    contexts = policy.get("contexts", [])
    checks = policy.get("checks", [])
    require(isinstance(contexts, list) and all(isinstance(name, str) and name for name in contexts), "invalid branch required check contexts")
    require(isinstance(checks, list), "invalid branch required check bindings")
    bindings: dict[str, int] = {}
    for item in checks:
        require(isinstance(item, dict), "invalid branch required check binding")
        bind_required_check(bindings, item.get("context"), item.get("app_id"), expected_app_id)
    ruleset_names: set[str] = set()
    for page in rules_pages:
        require(isinstance(page, list), "effective branch rules page is invalid")
        for rule in page:
            if isinstance(rule, dict) and rule.get("type") == "required_status_checks":
                ruleset_checks = rule.get("parameters", {}).get("required_status_checks", [])
                require(isinstance(ruleset_checks, list), "invalid ruleset required checks")
                for item in ruleset_checks:
                    require(isinstance(item, dict), "invalid ruleset required check binding")
                    name = item.get("context")
                    bind_required_check(bindings, name, item.get("integration_id"), expected_app_id)
                    ruleset_names.add(name)
    names = sorted(set(contexts) | ruleset_names)
    require(bool(names), "protected branch has no required checks")
    unbound = sorted(set(names) - set(bindings))
    require(not unbound, f"required checks are not app-bound by branch protection: {unbound}")
    return names, bindings


def head_applicable_required_checks(
    repository: str,
    branch_checks: list[str],
    contract_checks: list[str],
) -> list[str]:
    """Bind the contract to the complete effective branch policy."""

    branch_set = set(branch_checks)
    contract_set = set(contract_checks)
    pr_only = set(PR_ONLY_REQUIRED_CHECKS.get(repository, frozenset()))
    require(
        pr_only <= branch_set,
        "pinned PR-only required checks are absent from branch protection",
    )
    head_checks = branch_set - pr_only
    require(
        contract_set == head_checks,
        "contract exact-head checks do not match effective branch protection",
    )
    return sorted(head_checks)


def latest_check_conclusions(check_pages: list[Any]) -> dict[tuple[str, int], str | None]:
    runs: list[dict[str, Any]] = []
    for page in check_pages:
        require(isinstance(page, dict) and isinstance(page.get("check_runs"), list), "check-runs page is invalid")
        runs.extend(page["check_runs"])
    require(
        all(isinstance(item, dict) and isinstance(item.get("id"), int) for item in runs),
        "check run identity is invalid",
    )
    latest: dict[tuple[str, int], str | None] = {}
    for item in sorted(runs, key=lambda row: row["id"]):
        name = item.get("name")
        app_id = item.get("app", {}).get("id")
        if isinstance(name, str) and isinstance(app_id, int):
            latest[(name, app_id)] = item.get("conclusion")
    return latest


def action_run_and_job_ids(details_url: object, repository: str) -> tuple[int, int] | None:
    if not isinstance(details_url, str):
        return None
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/(\d+)/job/(\d+)",
        details_url,
    )
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def workflow_bound_check_conclusions(
    check_pages: list[Any],
    repository: str,
    source_sha: str,
    required_checks: list[str],
    bindings: dict[str, int],
    workflow_runs: dict[int, dict[str, Any]],
    jobs: dict[int, dict[str, Any]],
    protected_branch: str,
) -> dict[tuple[str, int], str | None]:
    expected = EXPECTED_CHECK_WORKFLOWS.get(repository)
    if not isinstance(expected, dict):
        raise PolicyError("required check workflow policy is missing")
    require(
        set(expected) >= set(required_checks),
        "required check workflow policy is incomplete",
    )
    candidates: dict[str, list[tuple[int, int, int, str | None]]] = {
        name: [] for name in required_checks
    }
    runs: list[dict[str, Any]] = []
    for page in check_pages:
        require(
            isinstance(page, dict) and isinstance(page.get("check_runs"), list),
            "check-runs page is invalid",
        )
        runs.extend(page["check_runs"])
    for item in runs:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        app_id = item.get("app", {}).get("id")
        if name not in candidates or app_id != bindings.get(str(name)):
            continue
        identities = action_run_and_job_ids(item.get("details_url"), repository)
        if identities is None:
            continue
        run_id, job_id = identities
        run = workflow_runs.get(run_id)
        job = jobs.get(job_id)
        if not isinstance(run, dict) or not isinstance(job, dict):
            continue
        if run.get("path") != expected[name]:
            # A same-name job from a different Actions workflow is not an
            # authoritative instance of the required check.
            continue
        require(
            run.get("head_sha") == source_sha
            and run.get("head_branch") == protected_branch
            and job.get("head_sha") == source_sha
            and job.get("run_id") == run_id
            and job.get("id") == job_id
            and job.get("name") == name,
            f"required check workflow identity is invalid: {name}",
        )
        allowed_events = (
            {"push", "workflow_dispatch"}
            if repository == CONTROLLER_REPOSITORY
            else {"push"}
        )
        require(
            run.get("event") in allowed_events,
            f"required check did not originate from the protected branch event: {name}",
        )
        attempt = job.get("run_attempt")
        check_id = item.get("id")
        if (
            not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt <= 0
            or not isinstance(check_id, int)
        ):
            raise PolicyError(f"required check job identity is invalid: {name}")
        candidates[name].append(
            (run_id, attempt, check_id, item.get("conclusion"))
        )
    latest: dict[tuple[str, int], str | None] = {}
    for name, values in candidates.items():
        if not values:
            continue
        newest = max(values, key=lambda item: item[2])
        latest_run, latest_attempt = newest[:2]
        current = [
            item
            for item in values
            if item[0] == latest_run and item[1] == latest_attempt
        ]
        require(
            len(current) == 1,
            f"required check has duplicate jobs in its authoritative workflow: {name}",
        )
        latest[(name, bindings[name])] = current[0][3]
    return latest


def load_workflow_bound_check_conclusions(
    repository: str,
    source_sha: str,
    required_checks: list[str],
    bindings: dict[str, int],
    protected_branch: str,
    *,
    administration: bool = False,
) -> dict[tuple[str, int], str | None]:
    pages = api_pages(
        f"repos/{repository}/commits/{source_sha}/check-runs?per_page=100",
        administration=administration,
    )
    workflow_runs: dict[int, dict[str, Any]] = {}
    jobs: dict[int, dict[str, Any]] = {}
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("check_runs"), list):
            continue
        for item in page["check_runs"]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            app_id = item.get("app", {}).get("id")
            if name not in required_checks or app_id != bindings.get(str(name)):
                continue
            identities = action_run_and_job_ids(item.get("details_url"), repository)
            if identities is None:
                continue
            run_id, job_id = identities
            if run_id not in workflow_runs:
                workflow_runs[run_id] = api_json(
                    f"repos/{repository}/actions/runs/{run_id}",
                    administration=administration,
                )
            if job_id not in jobs:
                jobs[job_id] = api_json(
                    f"repos/{repository}/actions/jobs/{job_id}",
                    administration=administration,
                )
    return workflow_bound_check_conclusions(
        pages,
        repository,
        source_sha,
        required_checks,
        bindings,
        workflow_runs,
        jobs,
        protected_branch,
    )


def validate_workflow_definition_bytes(
    repository: str,
    source_sha: str,
    path: str,
    raw: bytes,
) -> None:
    expected = EXPECTED_CHECK_WORKFLOW_SHA256.get(repository, {}).get(path)
    require(
        isinstance(expected, str) and DIGEST.fullmatch(expected) is not None,
        f"required check workflow digest policy is missing: {repository}:{path}",
    )
    require(
        hashlib.sha256(raw).hexdigest() == expected,
        f"required check workflow definition drift: {repository}:{path}",
    )
    validate_workflow_action_references(repository, source_sha, path, raw)


def validate_local_action_dockerfile(
    repository: str,
    source_sha: str,
    action_path: str,
) -> None:
    dockerfile_path = (Path(action_path).parent / "Dockerfile").as_posix()
    raw = repository_file_bytes(repository, source_sha, dockerfile_path)
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError(
            f"required check local-action Dockerfile is not UTF-8: {dockerfile_path}"
        ) from error

    logical_lines: list[str] = []
    pending = ""
    for physical_line in source.splitlines():
        line = physical_line.rstrip()
        pending = f"{pending}{line.lstrip()}" if pending else line
        if pending.endswith("\\"):
            pending = f"{pending[:-1].rstrip()} "
            continue
        logical_lines.append(pending)
        pending = ""
    require(
        not pending,
        f"required check local-action Dockerfile has an incomplete instruction: {dockerfile_path}",
    )

    stages: set[str] = set()
    from_count = 0
    for logical_line in logical_lines:
        stripped = logical_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^FROM\s+(.+)$", stripped)
        if match is None:
            continue
        from_count += 1
        arguments = match.group(1).split()
        while arguments and arguments[0].startswith("--"):
            arguments.pop(0)
        require(
            bool(arguments),
            f"required check local-action Dockerfile has an invalid FROM: {dockerfile_path}",
        )
        base = arguments.pop(0)
        normalized_base = base.lower()
        require(
            "$" not in base
            and (
                normalized_base == "scratch"
                or normalized_base in stages
                or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", base) is not None
            ),
            f"required check local-action Dockerfile uses a mutable base: {dockerfile_path}:{base}",
        )
        if len(arguments) >= 2 and arguments[0].lower() == "as":
            stage = arguments[1].lower()
            require(
                re.fullmatch(r"[a-z0-9_.-]+", stage) is not None,
                f"required check local-action Dockerfile has an invalid stage: {dockerfile_path}",
            )
            stages.add(stage)
    require(
        from_count > 0,
        f"required check local-action Dockerfile has no FROM instruction: {dockerfile_path}",
    )


def validate_workflow_action_references(
    repository: str,
    source_sha: str,
    path: str,
    raw: bytes,
    seen: frozenset[str] = frozenset(),
) -> None:
    require(path not in seen, f"required check local action cycle: {path}")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError(f"required check workflow is not UTF-8: {path}") from error
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise PolicyError("pinned workflow parser is unavailable") from error
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as error:
        raise PolicyError(f"required check workflow YAML is invalid: {path}") from error
    require(isinstance(document, dict), f"required check workflow is invalid: {path}")
    runs = document.get("runs")
    if isinstance(runs, dict) and runs.get("using") == "docker":
        image = runs.get("image")
        if not isinstance(image, str) or not image:
            raise PolicyError(
                f"required check local container action image is invalid: {path}"
            )
        if image == "Dockerfile":
            validate_local_action_dockerfile(repository, source_sha, path)
        else:
            require(
                re.fullmatch(
                    r"docker://[^\s@]+@sha256:[0-9a-f]{64}",
                    image,
                )
                is not None,
                f"required check local container action image is mutable: {path}:{image}",
            )
    references: list[str] = []

    def collect_references(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "uses":
                    require(
                        isinstance(child, str) and bool(child),
                        f"required check action reference is invalid: {path}",
                    )
                    references.append(child)
                else:
                    collect_references(child)
        elif isinstance(value, list):
            for child in value:
                collect_references(child)

    collect_references(document)
    for reference in references:
        reference = reference.split(" #", 1)[0].strip()
        if reference.startswith("./"):
            relative = reference[2:].rstrip("/")
            require(
                bool(relative)
                and not relative.startswith("/")
                and all(part not in {"", ".", ".."} for part in relative.split("/")),
                f"required check local action path is invalid: {path}:{reference}",
            )
            candidates = (
                [relative]
                if relative.endswith((".yml", ".yaml"))
                else [f"{relative}/action.yml", f"{relative}/action.yaml"]
            )
            nested_raw: bytes | None = None
            nested_path = ""
            for candidate in candidates:
                try:
                    nested_raw = repository_file_bytes(
                        repository,
                        source_sha,
                        candidate,
                    )
                except urllib.error.HTTPError as error:
                    if error.code != 404 or candidate == candidates[-1]:
                        raise
                    continue
                nested_path = candidate
                break
            require(
                nested_raw is not None and bool(nested_path),
                f"required check local action is missing: {path}:{reference}",
            )
            validate_workflow_action_references(
                repository,
                source_sha,
                nested_path,
                cast(bytes, nested_raw),
                seen | {path},
            )
            continue
        if reference.startswith("docker://"):
            require(
                re.fullmatch(
                    r"docker://[^\s@]+@sha256:[0-9a-f]{64}",
                    reference,
                )
                is not None,
                f"required check uses a mutable container action: {path}:{reference}",
            )
            continue
        require(
            re.fullmatch(r"[^\s@]+@[0-9a-f]{40}", reference) is not None,
            f"required check uses a mutable external action: {path}:{reference}",
        )


def validate_workflow_executable_bytes(
    repository: str,
    workflow_path: str,
    executable_path: str,
    raw: bytes,
) -> None:
    expected = EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256.get(repository, {}).get(
        workflow_path,
        {},
    ).get(executable_path)
    require(
        isinstance(expected, str) and DIGEST.fullmatch(expected) is not None,
        f"required check executable digest policy is missing: {repository}:{executable_path}",
    )
    require(
        hashlib.sha256(raw).hexdigest() == expected,
        f"required check executable drift: {repository}:{executable_path}",
    )


def is_exact_local_repository_source(
    repository: str,
    source_sha: str,
    local_repository: str | None,
    checkout_sha: str,
) -> bool:
    return repository == local_repository and source_sha == checkout_sha


def exact_local_repository_file_bytes(
    repository: str,
    source_sha: str,
    path: str,
) -> bytes | None:
    local_repository = os.environ.get("GITHUB_REPOSITORY")
    if repository != local_repository:
        return None
    checkout_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if not is_exact_local_repository_source(
        repository,
        source_sha,
        local_repository,
        checkout_sha,
    ):
        return None
    local_path = Path(path)
    require(
        local_path.is_file() and not local_path.is_symlink(),
        f"required source file is missing or unsafe: {path}",
    )
    return local_path.read_bytes()


def repository_file_bytes(
    repository: str,
    source_sha: str,
    path: str,
    *,
    administration: bool = False,
) -> bytes:
    require(SHA.fullmatch(source_sha) is not None, "repository file source SHA is invalid")
    local_bytes = exact_local_repository_file_bytes(repository, source_sha, path)
    if local_bytes is not None:
        return local_bytes
    encoded_path = urllib.parse.quote(path, safe="/")
    value = api_json(
        f"repos/{repository}/contents/{encoded_path}?ref={source_sha}",
        administration=administration,
    )
    require(
        isinstance(value, dict)
        and value.get("type") == "file"
        and value.get("encoding") == "base64"
        and isinstance(value.get("content"), str),
        f"required source file evidence is invalid: {repository}:{path}",
    )
    try:
        return base64.b64decode("".join(value["content"].split()), validate=True)
    except ValueError as error:
        raise PolicyError(
            f"required source file encoding is invalid: {repository}:{path}"
        ) from error
def required_check_source_paths(repository: str) -> set[str]:
    workflow_bindings = EXPECTED_CHECK_WORKFLOW_SHA256.get(repository)
    executable_bindings = EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256.get(
        repository,
        {},
    )
    require(
        isinstance(workflow_bindings, dict) and bool(workflow_bindings),
        f"required workflow source policy is missing: {repository}",
    )
    require(
        isinstance(executable_bindings, dict),
        f"required executable source policy is invalid: {repository}",
    )
    validated_workflows = cast(dict[str, str], workflow_bindings)
    validated_executables = cast(
        dict[str, dict[str, str]],
        executable_bindings,
    )
    paths = set(validated_workflows)
    for workflow, bindings in validated_executables.items():
        require(
            workflow in validated_workflows and isinstance(bindings, dict),
            f"required executable source policy is detached: {repository}:{workflow}",
        )
        paths.update(bindings)
    require(
        RELEASE_VALIDATOR_SOURCE_PATH not in paths,
        "release validator cannot bind its own source closure",
    )
    return paths


def source_closure_fingerprint(
    entries: list[dict[str, Any]],
    repository: str,
) -> str:
    """Fingerprint the complete exact-source tree used by required checks.

    The release validator excludes itself to avoid a literal hash cycle. The
    controller's reviewed candidate JSON is also excluded because its
    controller source binding is an already-reviewed policy-base ancestor.
    Every other blob/commit is included, so an omitted direct or transitive
    check executable cannot leave the closure unchanged.
    """

    records: dict[str, bytes] = {}
    for entry in entries:
        require(isinstance(entry, dict), "required source tree entry is invalid")
        path = entry.get("path")
        mode = entry.get("mode")
        kind = entry.get("type")
        sha = entry.get("sha")
        require(
            isinstance(path, str)
            and path != ""
            and "\0" not in path
            and "\n" not in path
            and isinstance(mode, str)
            and mode in {"100644", "100755", "120000", "160000"}
            and kind in {"blob", "commit"}
            and isinstance(sha, str)
            and SHA.fullmatch(sha) is not None,
            "required source tree entry is invalid",
        )
        validated_path = cast(str, path)
        if validated_path == RELEASE_VALIDATOR_SOURCE_PATH or (
            repository == CONTROLLER_REPOSITORY
            and validated_path.startswith("config/releases/")
            and validated_path.endswith(".json")
        ):
            continue
        require(validated_path not in records, "required source tree contains duplicate paths")
        records[validated_path] = f"{mode}\0{kind}\0{validated_path}\0{sha}\n".encode()
    require(bool(records), "required source tree is empty")
    return hashlib.sha256(b"".join(records[path] for path in sorted(records))).hexdigest()


def local_source_tree_entries(source_sha: str) -> list[dict[str, Any]]:
    raw = subprocess.check_output(
        ["git", "ls-tree", "-r", "-z", source_sha],
    )
    entries: list[dict[str, Any]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, kind, sha = metadata.decode("ascii").split()
            path = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise PolicyError("local required source tree is invalid") from error
        entries.append({"mode": mode, "type": kind, "sha": sha, "path": path})
    return entries


def validate_required_check_source_closure(
    repository: str,
    source_sha: str,
    *,
    administration: bool = False,
) -> None:
    expected = EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256.get(repository)
    require(
        isinstance(expected, str) and DIGEST.fullmatch(expected) is not None,
        f"required source closure policy is missing: {repository}",
    )
    local_repository = os.environ.get("GITHUB_REPOSITORY")
    checkout_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if is_exact_local_repository_source(
        repository,
        source_sha,
        local_repository,
        checkout_sha,
    ):
        entries = local_source_tree_entries(source_sha)
    else:
        commit = api_json(
            f"repos/{repository}/git/commits/{source_sha}",
            administration=administration,
        )
        require(
            isinstance(commit, dict)
            and commit.get("sha") == source_sha
            and isinstance(commit.get("tree"), dict)
            and isinstance(commit["tree"].get("sha"), str)
            and SHA.fullmatch(commit["tree"]["sha"]) is not None,
            f"required source commit tree is invalid: {repository}",
        )
        tree = api_json(
            f"repos/{repository}/git/trees/{commit['tree']['sha']}?recursive=1",
            administration=administration,
        )
        require(
            isinstance(tree, dict)
            and tree.get("truncated") is False
            and isinstance(tree.get("tree"), list),
            f"required source tree is incomplete: {repository}",
        )
        entries = [
            entry
            for entry in tree["tree"]
            if isinstance(entry, dict) and entry.get("type") != "tree"
        ]
    observed = source_closure_fingerprint(entries, repository)
    require(observed == expected, f"required source closure drift: {repository}")


def validate_required_check_workflow_definitions(
    repository: str,
    source_sha: str,
    required_checks: list[str],
    *,
    administration: bool = False,
) -> None:
    validate_required_check_source_closure(
        repository,
        source_sha,
        administration=administration,
    )
    paths = EXPECTED_CHECK_WORKFLOWS.get(repository)
    if not isinstance(paths, dict):
        raise PolicyError("required check workflow policy is missing")
    required_paths: set[str] = set()
    for name in required_checks:
        workflow_path = paths.get(name)
        if not isinstance(workflow_path, str):
            raise PolicyError("required check workflow policy is incomplete")
        required_paths.add(workflow_path)
    for path in sorted(required_paths):
        raw = repository_file_bytes(
            repository,
            source_sha,
            path,
            administration=administration,
        )
        validate_workflow_definition_bytes(repository, source_sha, path, raw)
        executable_policy = EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256.get(
            repository,
            {},
        ).get(path, {})
        if path == ".github/workflows/production-orchestrator-contract.yml":
            require(
                bool(executable_policy),
                f"required check executable digest policy is missing: {repository}:{path}",
            )
        for executable_path, expected_hash in executable_policy.items():
            require(
                DIGEST.fullmatch(expected_hash) is not None,
                f"required check executable digest is invalid: {repository}:{executable_path}",
            )
            executable = repository_file_bytes(
                repository,
                source_sha,
                executable_path,
                administration=administration,
            )
            validate_workflow_executable_bytes(
                repository,
                path,
                executable_path,
                executable,
            )


def validate_environment_document(value: object, environment: str) -> None:
    if not isinstance(value, dict):
        raise PolicyError("protected environment is missing")
    require(value.get("name") == environment, "protected environment is missing")
    rules = value.get("protection_rules")
    if not isinstance(rules, list):
        raise PolicyError("protected environment rules are invalid")
    reviewer_rules = [
        item
        for item in rules
        if isinstance(item, dict) and item.get("type") == "required_reviewers"
    ]
    require(len(reviewer_rules) == 1, "protected environment must have one required-reviewer rule")
    reviewer_rule = reviewer_rules[0]
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        raise PolicyError("protected environment has no required reviewers")
    reviewer_identities: set[tuple[str, int]] = set()
    for item in reviewers:
        reviewer_type = item.get("type") if isinstance(item, dict) else None
        reviewer = item.get("reviewer") if isinstance(item, dict) else None
        reviewer_id = reviewer.get("id") if isinstance(reviewer, dict) else None
        if (
            reviewer_type not in {"User", "Team"}
            or not isinstance(reviewer_id, int)
            or isinstance(reviewer_id, bool)
            or reviewer_id <= 0
        ):
            raise PolicyError("protected environment reviewer identity is invalid")
        reviewer_identities.add((str(reviewer_type), reviewer_id))
    require(
        len(reviewer_identities) == len(reviewers),
        "protected environment contains duplicate reviewers",
    )
    require(
        reviewer_identities == {("User", INDEPENDENT_REVIEWER_ID)},
        "protected environment approved reviewer identity drift",
    )
    require(reviewer_rule.get("prevent_self_review") is True, "protected environment permits self-review")
    require(value.get("can_admins_bypass") is False, "protected environment permits administrator bypass")
    branch_policy = value.get("deployment_branch_policy")
    require(
        isinstance(branch_policy, dict)
        and branch_policy.get("protected_branches") is True
        and branch_policy.get("custom_branch_policies") is False,
        "protected environment is not restricted to protected branches",
    )


def validate_environment_protection(repository: str, environment: str) -> None:
    encoded = urllib.parse.quote(environment, safe="")
    value = api_json(
        f"repos/{repository}/environments/{encoded}",
        administration=True,
    )
    validate_environment_document(value, environment)


def validate_repository_gates(
    contract: dict[str, Any],
    source_sha: str,
    phase: str,
    environment: str,
) -> tuple[list[str], dict[str, int]]:
    repository = os.environ["GITHUB_REPOSITORY"]
    branch_name = contract.get("default_branch")
    repository_data = api_json(f"repos/{repository}")
    require(repository_data.get("id") == contract.get("repository_id"), "stable repository ID mismatch")
    require(repository_data.get("default_branch") == branch_name, "default branch drift")
    require(repository_data.get("archived") is False and repository_data.get("disabled") is False, "repository unavailable")
    branch = api_json(f"repos/{repository}/branches/{branch_name}")
    require(branch.get("protected") is True, "default branch must be protected")
    require(branch.get("commit", {}).get("sha") == source_sha, "source SHA is not current protected branch head")
    if contract.get("require_verified_commit") is True:
        commit = api_json(f"repos/{repository}/commits/{source_sha}")
        require(commit.get("commit", {}).get("verification", {}).get("verified") is True, "exact source commit is not GitHub-verified")
    contract_checks = contract.get("required_checks")
    if not isinstance(contract_checks, list):
        raise PolicyError("invalid required_checks")
    require(all(isinstance(item, str) and item for item in contract_checks), "invalid required_checks")
    expected_app_id = contract.get("required_check_app_id")
    if not isinstance(expected_app_id, int) or expected_app_id <= 0:
        raise PolicyError("required check app ID is invalid")
    branch_checks, bindings = required_check_bindings(
        branch,
        api_pages(
            f"repos/{repository}/rules/branches/{branch_name}?per_page=100",
            administration=True,
        ),
        expected_app_id,
    )
    required_checks = head_applicable_required_checks(
        repository,
        branch_checks,
        contract_checks,
    )
    validate_required_check_workflow_definitions(
        repository,
        source_sha,
        required_checks,
    )
    latest = load_workflow_bound_check_conclusions(
        repository,
        source_sha,
        required_checks,
        bindings,
        str(branch_name),
    )
    missing = [name for name in required_checks if latest.get((name, bindings[name])) != "success"]
    require(not missing, f"required exact-head checks are not successful from the bound app: {missing}")
    if phase != "plan":
        require(bool(environment), f"{phase} protected environment is missing")
        validate_environment_protection(repository, environment)
    return required_checks, bindings


def validate_candidate_document(
    raw: bytes,
    expected_hash: str,
    release_id: str,
    repository: str,
    source_sha: str,
    contract_sha256: str,
    images: list[Any],
    previous_images: list[Any],
) -> dict[str, Any]:
    require(len(raw) <= 1_000_000, "candidate file exceeds size limit")
    require(hashlib.sha256(raw).hexdigest() == expected_hash, "candidate file SHA-256 mismatch")
    candidate = json.loads(raw)
    require(isinstance(candidate, dict), "candidate must be an object")
    require(candidate.get("schema_version") == CANDIDATE_SCHEMA, "candidate schema mismatch")
    require(candidate.get("template") is False, "template candidate cannot be admitted")
    require(candidate.get("release_id") == release_id, "candidate release ID mismatch")
    for field, pattern, zero in (
        ("controller_sha", SHA, "0" * 40),
        ("source_lock_sha", SHA, "0" * 40),
        ("runtime_candidate_sha256", DIGEST, ZERO64),
    ):
        value = candidate.get(field)
        require(isinstance(value, str) and pattern.fullmatch(value) is not None and value != zero, f"candidate {field} is invalid")
    safety = candidate.get("safety")
    require(isinstance(safety, dict) and set(safety) == CANDIDATE_SAFETY_KEYS, "candidate safety controls are incomplete or unexpected")
    require(all(value is False for value in safety.values()), "candidate enables an external/live effect")
    components = candidate.get("components")
    require(isinstance(components, list), "candidate components must be an array")
    by_repository: dict[str, dict[str, Any]] = {}
    for item in components:
        require(isinstance(item, dict), "candidate component must be an object")
        name = item.get("repository")
        require(isinstance(name, str) and name in CATALOG_REPOSITORIES, "candidate contains an unexpected repository")
        require(name not in by_repository, f"candidate contains duplicate repository: {name}")
        by_repository[name] = item
    require(set(by_repository) == CATALOG_REPOSITORIES, "candidate does not cover the exact protected catalog")
    require(
        by_repository[CONTROLLER_REPOSITORY].get("source_sha") == candidate["controller_sha"],
        "candidate controller policy-base binding mismatch",
    )
    component = by_repository[repository]
    require(component.get("enabled") is True, "candidate disables a required repository")
    require(component.get("source_sha") == source_sha, "candidate source SHA mismatch")
    require(component.get("contract_sha256") == contract_sha256, "candidate contract SHA-256 mismatch")
    require(component.get("images") == images, "candidate image input mismatch")
    require(component.get("previous_images") == previous_images, "candidate rollback image input mismatch")
    return candidate


def validate_phase_blockers(blockers: object, phase: str) -> list[str]:
    if not isinstance(blockers, list):
        raise PolicyError("contract blockers are invalid")
    require(all(isinstance(item, str) and item for item in blockers), "contract blockers are invalid")
    values = [item for item in blockers if isinstance(item, str)]
    if phase != "plan":
        require(not values, f"{phase} is blocked by unresolved contract blockers")
    return values


def download_and_validate_candidate(
    expected_hash: str,
    release_id: str,
    repository: str,
    source_sha: str,
    contract_sha256: str,
    images: list[Any],
    previous_images: list[Any],
) -> str:
    controller = api_json(f"repos/{CONTROLLER_REPOSITORY}", administration=True)
    require(controller.get("id") == 1314230781, "controller stable repository ID mismatch")
    require(controller.get("default_branch") == CONTROLLER_BRANCH, "controller protected branch drift")
    require(controller.get("archived") is False and controller.get("disabled") is False, "controller repository unavailable")
    encoded_branch = urllib.parse.quote(CONTROLLER_BRANCH, safe="")
    branch = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/branches/{encoded_branch}",
        administration=True,
    )
    controller_head = branch.get("commit", {}).get("sha")
    require(branch.get("protected") is True, "controller release branch is not protected")
    require(
        isinstance(controller_head, str)
        and SHA.fullmatch(controller_head) is not None,
        "controller protected head is invalid",
    )
    controller_commit = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/commits/{controller_head}",
        administration=True,
    )
    require(
        controller_commit.get("commit", {}).get("verification", {}).get("verified") is True,
        "controller protected head is not GitHub-verified",
    )
    controller_checks, controller_bindings = required_check_bindings(
        branch,
        api_pages(
            f"repos/{CONTROLLER_REPOSITORY}/rules/branches/{encoded_branch}?per_page=100",
            administration=True,
        ),
        15368,
    )
    validate_required_check_workflow_definitions(
        CONTROLLER_REPOSITORY,
        controller_head,
        controller_checks,
        administration=True,
    )
    controller_latest = load_workflow_bound_check_conclusions(
        CONTROLLER_REPOSITORY,
        controller_head,
        controller_checks,
        controller_bindings,
        CONTROLLER_BRANCH,
        administration=True,
    )
    controller_missing = [
        name
        for name in controller_checks
        if controller_latest.get((name, controller_bindings[name])) != "success"
    ]
    require(
        not controller_missing,
        f"controller required exact-head checks are not successful from the bound app: {controller_missing}",
    )
    path = urllib.parse.quote(f"config/releases/{release_id}.json", safe="/")
    value = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/contents/{path}?ref={controller_head}",
        administration=True,
    )
    require(
        isinstance(value, dict)
        and value.get("type") == "file"
        and value.get("encoding") == "base64"
        and isinstance(value.get("content"), str),
        "reviewed candidate file is missing or invalid",
    )
    try:
        raw = base64.b64decode("".join(value["content"].split()), validate=True)
    except ValueError as exc:
        raise PolicyError("reviewed candidate file is not valid base64") from exc
    validate_candidate_document(
        raw,
        expected_hash,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    controller_sha = json.loads(raw).get("controller_sha")
    comparison = api_json(
        f"repos/{CONTROLLER_REPOSITORY}/compare/{controller_sha}...{controller_head}",
        administration=True,
    )
    require(
        isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"},
        "candidate controller policy base is not an ancestor of its reviewed file",
    )
    return controller_head


def recheck_protected_gates() -> int:
    phase = os.environ["PHASE"]
    source_sha = os.environ["SOURCE_SHA"]
    release_id = os.environ["RELEASE_ID"]
    candidate_sha256 = os.environ["CANDIDATE_SHA256"]
    prior_hash = os.environ["PRIOR_EVIDENCE_SHA256"]
    prior_run_text = os.environ["PRIOR_EVIDENCE_RUN_ID"]
    preapproval_text = os.environ["PREAPPROVAL_EVIDENCE_B64"]
    require(phase in PREVIOUS_PHASE, "post-approval recheck requires a protected phase")
    require(SHA.fullmatch(source_sha) is not None and source_sha != "0" * 40, "source_sha must be nonzero lowercase 40-hex")
    require(RELEASE.fullmatch(release_id) is not None, "invalid release_id")
    require(DIGEST.fullmatch(candidate_sha256) is not None and candidate_sha256 != ZERO64, "candidate_sha256 must be nonzero lowercase 64-hex")
    require(DIGEST.fullmatch(prior_hash) is not None and prior_hash != ZERO64, "protected recheck requires nonzero prior evidence")
    require(prior_run_text.isdigit() and int(prior_run_text) > 0, "protected recheck requires a positive prior evidence run ID")
    require(prior_run_text != os.environ["GITHUB_RUN_ID"], "prior evidence cannot come from the current run")
    prior_run_id = int(prior_run_text)
    require(len(preapproval_text) <= 2_000_000, "pre-approval evidence is too large")
    try:
        preapproval = json.loads(base64.b64decode(preapproval_text, validate=True))
    except (ValueError, json.JSONDecodeError) as error:
        raise PolicyError("pre-approval evidence is invalid") from error
    require(isinstance(preapproval, dict), "pre-approval evidence must be an object")
    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "release contract is missing or unsafe")
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    require(isinstance(contract, dict) and contract.get("schema_version") == SCHEMA, "unexpected release contract schema")
    repository = os.environ["GITHUB_REPOSITORY"]
    require(contract.get("repository") == repository, "contract repository mismatch")
    branch_name = contract.get("default_branch")
    require(branch_name == os.environ["GITHUB_REF_NAME"] and os.environ["GITHUB_REF"] == f"refs/heads/{branch_name}", "workflow must run from the contract default branch")
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checkout_sha == source_sha, "checkout does not match source_sha")
    blockers = validate_phase_blockers(contract.get("blockers"), phase)
    require(contract.get("deployment_authority") is True, "protected recheck requires deployment authority")
    environment = contract.get("environments", {}).get(phase, "")
    expected_environment = {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }[phase]
    require(environment == expected_environment, f"{phase} protected environment mismatch")
    required_checks, bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )
    try:
        images = json.loads(os.environ["IMAGES_JSON"])
        previous_images = json.loads(os.environ["PREVIOUS_IMAGES_JSON"])
    except json.JSONDecodeError as error:
        raise PolicyError(f"image input is not valid JSON: {error}") from error
    require(isinstance(images, list) and isinstance(previous_images, list), "image inputs must be arrays")
    policy = contract.get("artifact_policy")
    require(isinstance(policy, dict), "artifact_policy must be an object")
    validate_images(images, previous_images, policy)
    contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
    controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    verify_supply_chain(images, policy, repository, branch_name, source_sha, exact_source=True)
    verify_supply_chain(previous_images, policy, repository, branch_name, source_sha, exact_source=False)
    previous_phase = PREVIOUS_PHASE[phase]
    prior = download_prior_evidence(
        repository,
        prior_run_id,
        f"codestra-release-intent-{previous_phase}-{source_sha}",
        prior_hash,
    )
    run = api_json(f"repos/{repository}/actions/runs/{prior_run_id}")
    require(run.get("head_sha") == source_sha, "prior evidence run used a different source SHA")
    validate_prior(
        prior,
        {
            "schema_version": "codestra.normalized-release-intent.v1",
            "repository": repository,
            "repository_id": contract["repository_id"],
            "phase": previous_phase,
            "release_id": release_id,
            "source_sha": source_sha,
            "candidate_sha256": candidate_sha256,
            "candidate_images": images,
            "previous_images": previous_images,
            "runtime_contacted": False,
            "production_changed": False,
            "external_effects_enabled": False,
            "protected_environment_approved": False,
            "protected_environment_job_completed": previous_phase != "plan",
            "status": "PASS",
        },
    )
    validate_prior(
        preapproval,
        {
            "schema_version": "codestra.normalized-release-intent.v1",
            "repository": repository,
            "repository_id": contract["repository_id"],
            "role": contract["role"],
            "phase": phase,
            "release_id": release_id,
            "source_sha": source_sha,
            "candidate_sha256": candidate_sha256,
            "prior_evidence_sha256": prior_hash,
            "prior_evidence_run_id": prior_run_id,
            "contract_sha256": contract_sha256,
            "controller_candidate_head_sha": controller_candidate_head,
            "contract_blockers": blockers,
            "required_checks": required_checks,
            "required_check_apps": {name: bindings[name] for name in required_checks},
            "candidate_images": images,
            "previous_images": previous_images,
            "deployment_authority": True,
            "protected_environment": environment,
            "protected_environment_approved": False,
            "protected_environment_job_completed": False,
            "runtime_contacted": False,
            "production_changed": False,
            "external_effects_enabled": False,
            "status": "PASS",
        },
    )
    final_controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    require(
        final_controller_candidate_head == controller_candidate_head,
        "controller protected head changed during protected gate recheck",
    )
    final_required_checks, final_bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )
    require(
        final_required_checks == required_checks and final_bindings == bindings,
        "required source-check policy changed during protected gate recheck",
    )
    post_gate_controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    require(
        post_gate_controller_candidate_head == controller_candidate_head,
        "controller protected head changed during final source-gate validation",
    )
    post_controller_required_checks, post_controller_bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )
    require(
        post_controller_required_checks == final_required_checks
        and post_controller_bindings == final_bindings,
        "source protected head or check policy changed during final controller validation",
    )
    print("PROTECTED_GATES_RECHECK=PASS")
    return 0


def validate_images(images: list[Any], previous_images: list[Any], policy: dict[str, Any]) -> list[str]:
    require(all(isinstance(item, str) and IMAGE.fullmatch(item) for item in images), "candidate images must be exact GHCR digests")
    require(all(isinstance(item, str) and IMAGE.fullmatch(item) for item in previous_images), "rollback images must be exact GHCR digests")
    require(len(images) == len(set(images)), "candidate image list contains duplicates")
    require(len(previous_images) == len(set(previous_images)), "rollback image list contains duplicates")
    minimum = policy.get("minimum_images")
    maximum = policy.get("maximum_images")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise PolicyError("contract image count must be integer")
    require(0 <= minimum == maximum, "contract must declare an exact image count")
    require(len(images) == maximum, "candidate image count violates contract")
    require(len(previous_images) == len(images), "rollback image count differs from candidate")
    if images:
        require(set(images) != set(previous_images), "rollback image set must differ from candidate image set")
    repository_value = policy.get("image_repositories")
    if not isinstance(repository_value, list):
        raise PolicyError("image repository policy must be an array")
    repositories = [item for item in repository_value if isinstance(item, str)]
    require(len(repositories) == len(repository_value), "image repository policy is invalid")
    require(len(repositories) == maximum, "image repository policy does not match the exact image count")
    require(len(repositories) == len(set(repositories)), "image repository policy contains duplicates")
    require(all(IMAGE_REPOSITORY.fullmatch(item) for item in repositories), "image repository policy is invalid")
    require(sorted(item.split("@", 1)[0] for item in images) == sorted(repositories), "candidate image repositories do not match the contract")
    require(sorted(item.split("@", 1)[0] for item in previous_images) == sorted(repositories), "rollback image repositories do not match the contract")
    return repositories


def validate_prior(prior: Any, expected: dict[str, Any]) -> None:
    require(isinstance(prior, dict), "prior evidence must be an object")
    for key, value in expected.items():
        require(prior.get(key) == value, f"prior evidence {key} mismatch")


def cosign_statements(raw: str) -> list[dict[str, Any]]:
    records: list[Any]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        records = parsed if isinstance(parsed, list) else [parsed]
    statements: list[dict[str, Any]] = []
    for record in records:
        require(isinstance(record, dict) and isinstance(record.get("payload"), str), "cosign attestation output is invalid")
        statement = json.loads(base64.b64decode(record["payload"], validate=True))
        require(isinstance(statement, dict), "cosign attestation statement is invalid")
        statements.append(statement)
    require(bool(statements), "cosign did not return an attestation statement")
    return statements


def download_prior_evidence(repository: str, run_id: int, expected_name: str, expected_hash: str) -> dict[str, Any]:
    run = api_json(f"repos/{repository}/actions/runs/{run_id}")
    require(run.get("id") == run_id, "prior run identity mismatch")
    require(run.get("event") == "workflow_dispatch", "prior evidence run was not manually dispatched")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "prior evidence run is not successful")
    require(run.get("path") == WORKFLOW, "prior evidence run used a different workflow")
    artifacts: list[dict[str, Any]] = []
    for page in api_pages(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"):
        require(isinstance(page, dict) and isinstance(page.get("artifacts"), list), "prior artifacts page is invalid")
        artifacts.extend(page["artifacts"])
    matches = [item for item in artifacts if item.get("name") == expected_name and item.get("expired") is False]
    require(len(matches) == 1, "prior release-intent artifact is missing, ambiguous, or expired")
    artifact = matches[0]
    require(artifact.get("workflow_run", {}).get("id") in (None, run_id), "prior artifact run binding mismatch")
    archive = download_artifact_archive(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        require(bundle.namelist() == ["release-intent.json"], "prior artifact archive has unexpected contents")
        info = bundle.getinfo("release-intent.json")
        require(not info.is_dir() and info.file_size <= 1_000_000, "prior evidence file is invalid")
        prior_bytes = bundle.read(info)
    require(hashlib.sha256(prior_bytes).hexdigest() == expected_hash, "prior evidence hash mismatch")
    return json.loads(prior_bytes)


def verify_supply_chain(
    images: list[str],
    policy: dict[str, Any],
    repository: str,
    branch: str,
    source_sha: str,
    *,
    exact_source: bool,
) -> None:
    require_sbom = policy.get("require_sbom")
    require_provenance = policy.get("require_provenance")
    require_signature = policy.get("require_signature")
    require(all(type(value) is bool for value in (require_sbom, require_provenance, require_signature)), "supply-chain requirements must be boolean")
    if not (require_sbom or require_provenance or require_signature):
        return
    verifier = policy.get("attestation_verifier")
    storage = policy.get("attestation_storage")
    workflow = policy.get("signer_workflow")
    predicate_type = policy.get("provenance_predicate_type", "https://slsa.dev/provenance/v1")
    require(verifier in {"github", "cosign"}, "attestation verifier is missing")
    require(storage in {"github", "oci"}, "attestation storage is missing")
    require(verifier != "cosign" or storage == "oci", "Cosign attestations must use OCI storage")
    require(isinstance(workflow, str) and workflow.startswith(".github/workflows/") and workflow.endswith((".yml", ".yaml")), "signer workflow is invalid")
    require(isinstance(predicate_type, str) and predicate_type.startswith("https://"), "provenance predicate type is invalid")
    subprocess.run(
        ["docker", "login", "ghcr.io", "--username", os.environ["GITHUB_ACTOR"], "--password-stdin"],
        input=os.environ["GH_TOKEN"],
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    signer = f"{repository}/{workflow}"
    identity = f"https://github.com/{signer}@refs/heads/{branch}"
    common = ["--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"]
    for image in images:
        if verifier == "github":
            require(not require_signature, "GitHub-attestation policy cannot claim a standalone image signature")
            if require_provenance:
                command = [
                    "gh", "attestation", "verify", f"oci://{image}",
                    "--repo", repository,
                    "--signer-workflow", signer,
                    "--source-ref", f"refs/heads/{branch}",
                    "--predicate-type", predicate_type,
                    "--deny-self-hosted-runners",
                    "--format", "json",
                ]
                if exact_source:
                    command.extend(["--source-digest", source_sha])
                if storage == "oci":
                    command.append("--bundle-from-oci")
                raw = subprocess.check_output(command, text=True)
                require(bool(json.loads(raw)), f"provenance attestation is missing for {image}")
            if require_sbom:
                raw = subprocess.check_output(
                    ["docker", "buildx", "imagetools", "inspect", image, "--format", "{{ json .SBOM }}"],
                    text=True,
                )
                require(bool(json.loads(raw)), f"SBOM attestation is missing for {image}")
        else:
            if require_signature:
                command = ["cosign", "verify", *common]
                if exact_source:
                    command.extend(["--annotations", f"codestra.source_sha={source_sha}"])
                subprocess.run([*command, image], check=True, stdout=subprocess.DEVNULL)
            if require_sbom:
                subprocess.run(["cosign", "verify-attestation", "--type", "spdxjson", *common, image], check=True, stdout=subprocess.DEVNULL)
            if require_provenance:
                provenance = subprocess.check_output(
                    ["cosign", "verify-attestation", "--type", "slsaprovenance1", *common, image],
                    text=True,
                )
                statements = cosign_statements(provenance)
                source_commits = {
                    commit
                    for statement in statements
                    for dependency in statement.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
                    if isinstance(dependency, dict)
                    for commit in [dependency.get("digest", {}).get("gitCommit")]
                    if isinstance(commit, str) and SHA.fullmatch(commit)
                }
                if exact_source:
                    require(
                        source_sha in source_commits,
                        f"signed provenance does not bind source SHA for {image}",
                    )
                else:
                    require(
                        bool(source_commits),
                        f"rollback provenance does not bind a source SHA for {image}",
                    )


def main() -> int:
    phase = os.environ["PHASE"]
    source_sha = os.environ["SOURCE_SHA"]
    release_id = os.environ["RELEASE_ID"]
    candidate_sha256 = os.environ["CANDIDATE_SHA256"]
    prior_hash = os.environ["PRIOR_EVIDENCE_SHA256"]
    prior_run_text = os.environ["PRIOR_EVIDENCE_RUN_ID"]
    require(phase in CONFIRMATIONS, "unsupported release phase")
    require(os.environ["CONFIRMATION"] == CONFIRMATIONS[phase], "confirmation mismatch")
    require(SHA.fullmatch(source_sha) is not None and source_sha != "0" * 40, "source_sha must be nonzero lowercase 40-hex")
    require(DIGEST.fullmatch(candidate_sha256) is not None and candidate_sha256 != ZERO64, "candidate_sha256 must be nonzero lowercase 64-hex")
    require(DIGEST.fullmatch(prior_hash) is not None, "prior evidence must be lowercase 64-hex")
    require(prior_run_text.isdigit(), "prior evidence run ID must be decimal")
    require(RELEASE.fullmatch(release_id) is not None, "invalid release_id")
    prior_run_id = int(prior_run_text)
    if phase == "plan":
        require(prior_hash == ZERO64 and prior_run_id == 0, "plan must use zero prior evidence")
    else:
        require(prior_hash != ZERO64 and prior_run_id > 0, f"{phase} requires prior-phase evidence")
        require(prior_run_text != os.environ["GITHUB_RUN_ID"], "prior evidence cannot come from the current run")

    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "release contract is missing or unsafe")
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    repository = os.environ["GITHUB_REPOSITORY"]
    require(isinstance(contract, dict) and contract.get("schema_version") == SCHEMA, "unexpected release contract schema")
    require(contract.get("repository") == repository, "contract repository mismatch")
    require(contract.get("release_intent_workflow") == WORKFLOW, "contract workflow mismatch")
    branch_name = contract.get("default_branch")
    require(branch_name == os.environ["GITHUB_REF_NAME"] and os.environ["GITHUB_REF"] == f"refs/heads/{branch_name}", "workflow must run from the contract default branch")
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checkout_sha == source_sha, "checkout does not match source_sha")
    require(not subprocess.check_output(["git", "status", "--porcelain"], text=True).strip(), "workspace is dirty")

    supported = contract.get("supported_phases")
    require(isinstance(supported, list) and phase in supported, f"phase {phase} is not supported")
    deployment_authority = contract.get("deployment_authority") is True
    if phase != "plan":
        require(deployment_authority, "repository is not a deployment authority")
    blockers = validate_phase_blockers(contract.get("blockers"), phase)
    environment = ""
    if phase != "plan":
        environment = contract.get("environments", {}).get(phase, "")
        expected_environment = {"staging": "staging-readonly", "canary": "production-readonly-canary", "production": "production"}[phase]
        require(environment == expected_environment, f"{phase} protected environment mismatch")
    required_checks, bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )

    try:
        images = json.loads(os.environ["IMAGES_JSON"])
        previous_images = json.loads(os.environ["PREVIOUS_IMAGES_JSON"])
    except json.JSONDecodeError as error:
        raise PolicyError(f"image input is not valid JSON: {error}") from error
    require(isinstance(images, list) and isinstance(previous_images, list), "image inputs must be arrays")
    policy = contract.get("artifact_policy")
    require(isinstance(policy, dict), "artifact_policy must be an object")
    require(policy.get("require_digest") is True, "digest-only artifacts are required")
    require(policy.get("allow_rebuild_after_staging") is False, "rebuild after staging must remain forbidden")
    require(policy.get("allow_retag_after_staging") is False, "retag after staging must remain forbidden")
    validate_images(images, previous_images, policy)
    contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
    controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    verify_supply_chain(images, policy, repository, branch_name, source_sha, exact_source=True)
    verify_supply_chain(previous_images, policy, repository, branch_name, source_sha, exact_source=False)

    safety = contract.get("safety")
    require(isinstance(safety, dict) and SAFETY_KEYS <= set(safety), "safety contract is incomplete")
    require(all(safety.get(key) is False for key in SAFETY_KEYS), "every external/live effect must remain disabled")
    if phase != "plan":
        previous_phase = PREVIOUS_PHASE[phase]
        prior = download_prior_evidence(repository, prior_run_id, f"codestra-release-intent-{previous_phase}-{source_sha}", prior_hash)
        run = api_json(f"repos/{repository}/actions/runs/{prior_run_id}")
        require(run.get("head_sha") == source_sha, "prior evidence run used a different source SHA")
        validate_prior(
            prior,
            {
                "schema_version": "codestra.normalized-release-intent.v1",
                "repository": repository,
                "repository_id": contract["repository_id"],
                "phase": previous_phase,
                "release_id": release_id,
                "source_sha": source_sha,
                "candidate_sha256": candidate_sha256,
                "candidate_images": images,
                "previous_images": previous_images,
                "runtime_contacted": False,
                "production_changed": False,
                "external_effects_enabled": False,
                "protected_environment_approved": False,
                "protected_environment_job_completed": previous_phase != "plan",
                "status": "PASS",
            },
        )

    final_controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    require(
        final_controller_candidate_head == controller_candidate_head,
        "controller protected head changed during release-intent validation",
    )
    required_checks, bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )
    post_gate_controller_candidate_head = download_and_validate_candidate(
        candidate_sha256,
        release_id,
        repository,
        source_sha,
        contract_sha256,
        images,
        previous_images,
    )
    require(
        post_gate_controller_candidate_head == controller_candidate_head,
        "controller protected head changed during final source-gate validation",
    )
    post_controller_required_checks, post_controller_bindings = validate_repository_gates(
        contract,
        source_sha,
        phase,
        environment,
    )
    require(
        post_controller_required_checks == required_checks
        and post_controller_bindings == bindings,
        "source protected head or check policy changed during final controller validation",
    )

    evidence = {
        "schema_version": "codestra.normalized-release-intent.v1",
        "repository": repository,
        "repository_id": contract["repository_id"],
        "role": contract["role"],
        "phase": phase,
        "release_id": release_id,
        "source_sha": source_sha,
        "candidate_sha256": candidate_sha256,
        "prior_evidence_sha256": prior_hash,
        "prior_evidence_run_id": prior_run_id,
        "contract_sha256": contract_sha256,
        "controller_candidate_head_sha": post_gate_controller_candidate_head,
        "contract_blockers": blockers,
        "required_checks": required_checks,
        "required_check_apps": {name: bindings[name] for name in required_checks},
        "candidate_images": images,
        "previous_images": previous_images,
        "deployment_authority": deployment_authority,
        "protected_environment": environment or None,
        "protected_environment_approved": False,
        "protected_environment_job_completed": False,
        "runtime_contacted": False,
        "production_changed": False,
        "external_effects_enabled": False,
        "status": "PASS",
    }
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write(f"environment={environment}\n")
        stream.write(f"deployment_authority={str(deployment_authority).lower()}\n")
        stream.write(f"evidence_b64={base64.b64encode(encoded).decode()}\n")
        stream.write(f"evidence_sha256={hashlib.sha256(encoded).hexdigest()}\n")
    return 0


def self_test() -> int:
    global NO_REDIRECT_OPENER
    local_repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))["repository"]
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    os.environ.setdefault("GITHUB_REPOSITORY", local_repository)

    require(
        set(EXPECTED_CHECK_WORKFLOWS)
        == set(EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256),
        "required source closure catalog is incomplete",
    )
    validate_workflow_action_references(
        local_repository,
        checkout_sha,
        "synthetic-required-check.yml",
        (
            b"jobs:\n  test:\n    steps:\n"
            b"      - uses: actions/checkout@0123456789012345678901234567890123456789\n"
            b"      - uses: docker://example/check@sha256:"
            + b"a" * 64
            + b"\n"
        ),
    )
    for mutable_workflow in (
        b"jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7\n",
        b"jobs:\n  test:\n    steps:\n      - uses: docker://example/check:latest\n",
        b"jobs: {test: {steps: [{uses: owner/action@v1}]}}\n",
        b"jobs:\n  test:\n    steps:\n      - {'uses': owner/action@main}\n",
    ):
        try:
            validate_workflow_action_references(
                local_repository,
                checkout_sha,
                "synthetic-required-check.yml",
                mutable_workflow,
            )
        except PolicyError:
            pass
        else:
            raise PolicyError("negative mutable required-check action regression passed")
    repository_root = Path.cwd()
    with tempfile.TemporaryDirectory(
        prefix=".codestra-local-action-",
        dir=repository_root,
    ) as directory:
        action_directory = Path(directory)
        (action_directory / "action.yml").write_text(
            "name: unsafe-local-action\nruns:\n  using: composite\n  steps:\n"
            "    - uses: owner/action@main\n",
            encoding="utf-8",
        )
        relative_action = action_directory.relative_to(repository_root).as_posix()
        try:
            validate_workflow_action_references(
                local_repository,
                checkout_sha,
                "synthetic-local-action.yml",
                (
                    "jobs:\n  test:\n    steps:\n"
                    f"      - uses: ./{relative_action}\n"
                ).encode(),
            )
        except PolicyError:
            pass
        else:
            raise PolicyError("negative recursive local-action pin regression passed")
        (action_directory / "action.yml").write_text(
            "name: unsafe-container-action\nruns:\n  using: docker\n"
            "  image: docker://example/check:latest\n",
            encoding="utf-8",
        )
        try:
            validate_workflow_action_references(
                local_repository,
                checkout_sha,
                f"{relative_action}/action.yml",
                (action_directory / "action.yml").read_bytes(),
            )
        except PolicyError:
            pass
        else:
            raise PolicyError("negative local container-action pin regression passed")
        (action_directory / "action.yml").write_text(
            "name: unsafe-dockerfile-action\nruns:\n  using: docker\n"
            "  image: Dockerfile\n",
            encoding="utf-8",
        )
        (action_directory / "Dockerfile").write_text(
            "FROM example/base:latest\n",
            encoding="utf-8",
        )
        try:
            validate_workflow_action_references(
                local_repository,
                checkout_sha,
                f"{relative_action}/action.yml",
                (action_directory / "action.yml").read_bytes(),
            )
        except PolicyError:
            pass
        else:
            raise PolicyError("negative local-action Dockerfile pin regression passed")
        (action_directory / "Dockerfile").write_text(
            "FROM example/base@sha256:" + "a" * 64 + " AS build\n"
            "FROM build\n",
            encoding="utf-8",
        )
        validate_workflow_action_references(
            local_repository,
            checkout_sha,
            f"{relative_action}/action.yml",
            (action_directory / "action.yml").read_bytes(),
        )
    source_fixture_repository = CONTROLLER_REPOSITORY
    source_fixture = [
        {
            "mode": "100644",
            "type": "blob",
            "path": path,
            "sha": "2" * 40,
        }
        for path in sorted(required_check_source_paths(source_fixture_repository))
    ]
    source_fixture.append(
        {
            "mode": "100644",
            "type": "blob",
            "path": "tools/transitive-required-check-input.py",
            "sha": "5" * 40,
        }
    )
    source_fixture.extend(
        [
            {
                "mode": "100644",
                "type": "blob",
                "path": RELEASE_VALIDATOR_SOURCE_PATH,
                "sha": "1" * 40,
            },
            {
                "mode": "100644",
                "type": "blob",
                "path": "config/releases/release-test-001.json",
                "sha": "3" * 40,
            },
        ]
    )
    source_fingerprint = source_closure_fingerprint(
        source_fixture,
        source_fixture_repository,
    )
    require(
        source_fingerprint
        == source_closure_fingerprint(
            source_fixture[:-2]
            + [{**source_fixture[-2], "sha": "4" * 40}, source_fixture[-1]],
            source_fixture_repository,
        ),
        "release validator exclusion created a self-referential source closure",
    )
    require(
        source_fingerprint
        == source_closure_fingerprint(
            source_fixture[:-1]
            + [{**source_fixture[-1], "sha": "4" * 40}],
            source_fixture_repository,
        ),
        "candidate review created a self-referential source closure",
    )
    require(
        source_fingerprint != source_closure_fingerprint(
            [{**source_fixture[0], "sha": "4" * 40}, *source_fixture[1:]],
            source_fixture_repository,
        ),
        "required-check executable drift did not change the source closure",
    )
    require(
        source_fingerprint
        != source_closure_fingerprint(
            source_fixture[:-3]
            + [{**source_fixture[-3], "sha": "4" * 40}]
            + source_fixture[-2:],
            source_fixture_repository,
        ),
        "unlisted transitive executable drift did not change the source closure",
    )
    breero_quality_closure = {
        ".github/workflows/backend-production.yml",
        ".github/workflows/frontend-production.yml",
        ".github/workflows/release-images.yml",
        "apps/api/Dockerfile",
        "deploy/frontend/Dockerfile",
        "deploy/portals/Dockerfile",
        "scripts/ci/classify-quality-scope.sh",
        "scripts/ci/test-classify-quality-scope.sh",
        "scripts/ci/test-validate-breero-scope.sh",
        "scripts/ci/validate-breero-scope.sh",
    }
    require(
        breero_quality_closure
        <= set(
            EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256["appolon1908-hue/Breero.com"][
                ".github/workflows/quality.yml"
            ]
        ),
        "Breero quality workflow executable closure is incomplete",
    )
    workflow_path = ".github/workflows/production-orchestrator-contract.yml"
    workflow_bytes = Path(workflow_path).read_bytes()
    require(
        is_exact_local_repository_source(
            local_repository,
            checkout_sha,
            local_repository,
            checkout_sha,
        ),
        "exact local source-file binding regression failed",
    )
    stale_sha = ("0" if checkout_sha[0] != "0" else "1") + checkout_sha[1:]
    require(
        not is_exact_local_repository_source(
            local_repository,
            stale_sha,
            local_repository,
            checkout_sha,
        ),
        "stale source SHA incorrectly used local workflow bytes",
    )
    validate_workflow_definition_bytes(
        local_repository,
        checkout_sha,
        workflow_path,
        workflow_bytes,
    )
    try:
        validate_workflow_definition_bytes(
            local_repository,
            checkout_sha,
            workflow_path,
            workflow_bytes + b"\n",
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative required-check workflow digest regression passed")
    executable_path = ".codestra/validate-production-orchestrator-contract.py"
    executable_bytes = Path(executable_path).read_bytes()
    validate_workflow_executable_bytes(
        local_repository,
        workflow_path,
        executable_path,
        executable_bytes,
    )
    try:
        validate_workflow_executable_bytes(
            local_repository,
            workflow_path,
            executable_path,
            executable_bytes + b"\n",
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative required-check executable digest regression passed")
    require(
        head_applicable_required_checks(
            "appolon1908-hue/Infustruction-repo",
            ["orchestrator-contract", "validate", "validate-source"],
            ["orchestrator-contract", "validate", "validate-source"],
        )
        == ["orchestrator-contract", "validate", "validate-source"],
        "exact branch-required check regression failed",
    )
    try:
        head_applicable_required_checks(
            "appolon1908-hue/Infustruction-repo",
            ["orchestrator-contract", "validate", "validate-source"],
            ["orchestrator-contract", "validate-source"],
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative stale required-check contract regression passed")
    require(
        head_applicable_required_checks(
            "ingtrader21-spec/Middleware-",
            [
                "Validate middleware merge result",
                "Validate middleware source head",
                "connector-runtime-build",
                "orchestrator-contract",
                "validate",
            ],
            ["connector-runtime-build", "orchestrator-contract", "validate"],
        )
        == ["connector-runtime-build", "orchestrator-contract", "validate"],
        "PR-only required-check classification regression failed",
    )
    keycloak_head_checks = [
        "orchestrator-contract",
        "validate",
        "validate-merge-result",
        "validate-source",
    ]
    require(
        head_applicable_required_checks(
            "appolon1908-hue/Keycloak",
            keycloak_head_checks + ["bootstrap"],
            keycloak_head_checks,
        )
        == keycloak_head_checks,
        "Keycloak head/PR check alignment failed",
    )

    digest_a = "ghcr.io/example/app@sha256:" + "a" * 64
    digest_b = "ghcr.io/example/app@sha256:" + "b" * 64
    policy = {"minimum_images": 1, "maximum_images": 1, "image_repositories": ["ghcr.io/example/app"]}
    validate_images([digest_a], [digest_b], policy)
    for candidate, message in (
        (["ghcr.io/example/app:latest"], "mutable image tag"),
        ([], "incomplete candidate images"),
        (["ghcr.io/example/wrong@sha256:" + "a" * 64], "wrong image repository"),
    ):
        try:
            validate_images(candidate, [digest_b], policy)
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative regression passed: {message}")
    reordered_policy = {
        "minimum_images": 2,
        "maximum_images": 2,
        "image_repositories": ["ghcr.io/example/app", "ghcr.io/example/worker"],
    }
    app_a = "ghcr.io/example/app@sha256:" + "a" * 64
    worker_b = "ghcr.io/example/worker@sha256:" + "b" * 64
    try:
        validate_images([app_a, worker_b], [worker_b, app_a], reordered_policy)
    except PolicyError:
        pass
    else:
        raise PolicyError("negative reordered rollback regression passed")
    validate_artifact_storage_url("https://productionresultssa0.blob.core.windows.net/actions/results.zip?sig=test")
    for location in (
        "http://productionresultssa0.blob.core.windows.net/results.zip",
        "https://api.github.com/repos/example/archive.zip",
        "https://evil.example/results.zip",
    ):
        try:
            validate_artifact_storage_url(location)
        except PolicyError:
            pass
        else:
            raise PolicyError("negative artifact redirect regression passed")
    original_opener = NO_REDIRECT_OPENER

    class RedirectTestOpener:
        def __init__(self) -> None:
            self.requests: list[urllib.request.Request] = []

        def open(self, request: urllib.request.Request, timeout: int) -> io.BytesIO:
            del timeout
            self.requests.append(request)
            if request.full_url.startswith("https://api.github.com/"):
                require(
                    request.headers.get("Authorization") == "Bearer test-token",
                    "artifact API request omitted authorization",
                )
                headers = Message()
                headers["Location"] = (
                    "https://productionresultssa0.blob.core.windows.net/"
                    "actions/results.zip?sig=test"
                )
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "Found",
                    headers,
                    None,
                )
            require(
                request.headers.get("Authorization") is None,
                "GitHub authorization leaked to artifact storage",
            )
            return io.BytesIO(b"test-archive")

    redirect_opener = RedirectTestOpener()
    NO_REDIRECT_OPENER = redirect_opener
    os.environ.setdefault("GH_TOKEN", "test-token")
    try:
        require(
            download_artifact_archive("repos/example/actions/artifacts/1/zip")
            == b"test-archive",
            "artifact redirect regression returned unexpected content",
        )
        require(len(redirect_opener.requests) == 2, "artifact redirect did not use two explicit requests")
    finally:
        NO_REDIRECT_OPENER = original_opener
    expected = {"phase": "plan", "candidate_sha256": "c" * 64, "production_changed": False}
    validate_prior(deepcopy(expected), expected)
    for key, value in (("phase", "staging"), ("candidate_sha256", "d" * 64), ("production_changed", True)):
        mutation = deepcopy(expected)
        mutation[key] = value
        try:
            validate_prior(mutation, expected)
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative prior-evidence regression passed: {key}")
    statement = {"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": "e" * 40}}]}}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    require(cosign_statements(json.dumps({"payload": payload})) == [statement], "cosign statement regression failed")
    try:
        cosign_statements(json.dumps({"payload": "not-base64"}))
    except (PolicyError, ValueError):
        pass
    else:
        raise PolicyError("negative malformed cosign attestation regression passed")
    branch: dict[str, Any] = {"protection": {"required_status_checks": {"contexts": ["validate"], "checks": [{"context": "validate", "app_id": 15368}]}}}
    names, bindings = required_check_bindings(branch, [[]], 15368)
    require(names == ["validate"] and bindings == {"validate": 15368}, "app-binding positive regression failed")
    wrong = deepcopy(branch)
    wrong["protection"]["required_status_checks"]["checks"][0]["app_id"] = 1
    try:
        required_check_bindings(wrong, [[]], 15368)
    except PolicyError:
        pass
    else:
        raise PolicyError("negative wrong-app regression passed")
    latest = latest_check_conclusions(
        [
            {
                "check_runs": [
                    {
                        "id": 10,
                        "name": "validate",
                        "app": {"id": 15368},
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-09-08T00:00:00Z",
                        "completed_at": "2026-09-08T00:10:00Z",
                    },
                    {
                        "id": 11,
                        "name": "validate",
                        "app": {"id": 15368},
                        "status": "in_progress",
                        "conclusion": None,
                        "started_at": "2026-09-08T00:05:00Z",
                        "completed_at": None,
                    },
                ]
            }
        ]
    )
    require(
        latest[("validate", 15368)] is None,
        "newest pending check-run regression failed",
    )
    workflow_repository = "appolon1908-hue/Moneybee-Backend"
    workflow_sha = "a" * 40
    workflow_checks = [
        {
            "id": 20,
            "name": "orchestrator-contract",
            "app": {"id": 15368},
            "conclusion": "success",
            "details_url": (
                f"https://github.com/{workflow_repository}/actions/runs/200/job/2000"
            ),
        },
        {
            "id": 21,
            "name": "orchestrator-contract",
            "app": {"id": 15368},
            "conclusion": "success",
            "details_url": (
                f"https://github.com/{workflow_repository}/actions/runs/201/job/2010"
            ),
        },
    ]
    workflow_runs = {
        200: {
            "path": ".github/workflows/production-orchestrator-contract.yml",
            "head_sha": workflow_sha,
            "head_branch": "main",
            "event": "push",
        },
        201: {
            "path": ".github/workflows/spoof.yml",
            "head_sha": workflow_sha,
            "head_branch": "main",
            "event": "push",
        },
    }
    jobs = {
        2000: {
            "id": 2000,
            "run_id": 200,
            "run_attempt": 1,
            "name": "orchestrator-contract",
            "head_sha": workflow_sha,
        },
        2010: {
            "id": 2010,
            "run_id": 201,
            "run_attempt": 1,
            "name": "orchestrator-contract",
            "head_sha": workflow_sha,
        },
    }
    workflow_latest = workflow_bound_check_conclusions(
        [{"check_runs": workflow_checks}],
        workflow_repository,
        workflow_sha,
        ["orchestrator-contract"],
        {"orchestrator-contract": 15368},
        workflow_runs,
        jobs,
        "main",
    )
    require(
        workflow_latest[("orchestrator-contract", 15368)] == "success",
        "workflow-bound check regression failed",
    )
    try:
        workflow_bound_check_conclusions(
            [{"check_runs": [workflow_checks[0]]}],
            workflow_repository,
            workflow_sha,
            ["orchestrator-contract"],
            {"orchestrator-contract": 15368},
            {200: {**workflow_runs[200], "event": "pull_request"}},
            {2000: jobs[2000]},
            "main",
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative pull-request required-check regression passed")
    duplicate = deepcopy(workflow_checks[0])
    duplicate["id"] = 22
    duplicate["details_url"] = (
        f"https://github.com/{workflow_repository}/actions/runs/200/job/2001"
    )
    duplicate_jobs = {
        **jobs,
        2001: {**jobs[2000], "id": 2001},
    }
    try:
        workflow_bound_check_conclusions(
            [{"check_runs": [workflow_checks[0], duplicate]}],
            workflow_repository,
            workflow_sha,
            ["orchestrator-contract"],
            {"orchestrator-contract": 15368},
            workflow_runs,
            duplicate_jobs,
            "main",
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative duplicate required-check job regression passed")
    rerun_check = {
        **workflow_checks[0],
        "id": 23,
        "conclusion": None,
        "details_url": (
            f"https://github.com/{workflow_repository}/actions/runs/199/job/1990"
        ),
    }
    rerun_latest = workflow_bound_check_conclusions(
        [{"check_runs": [workflow_checks[0], rerun_check]}],
        workflow_repository,
        workflow_sha,
        ["orchestrator-contract"],
        {"orchestrator-contract": 15368},
        {
            **workflow_runs,
            199: {
                "path": ".github/workflows/production-orchestrator-contract.yml",
                "head_sha": workflow_sha,
                "head_branch": "main",
                "event": "push",
            },
        },
        {
            **jobs,
            1990: {
                "id": 1990,
                "run_id": 199,
                "run_attempt": 2,
                "name": "orchestrator-contract",
                "head_sha": workflow_sha,
            },
        },
        "main",
    )
    require(
        rerun_latest[("orchestrator-contract", 15368)] is None,
        "newest check identity did not supersede a higher workflow run ID",
    )
    protected_environment: dict[str, Any] = {
        "name": "production",
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {
                            "id": INDEPENDENT_REVIEWER_ID,
                            "login": "kazan555",
                        },
                    }
                ],
            }
        ],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }
    validate_environment_document(protected_environment, "production")
    for mutation_name, mutation in (
        (
            "missing environment reviewers",
            {
                **protected_environment,
                "protection_rules": [],
            },
        ),
        (
            "substituted environment reviewer",
            {
                **protected_environment,
                "protection_rules": [
                    {
                        **protected_environment["protection_rules"][0],
                        "reviewers": [
                            {
                                "type": "User",
                                "reviewer": {
                                    "id": INDEPENDENT_REVIEWER_ID + 1,
                                    "login": "substituted-reviewer",
                                },
                            }
                        ],
                    }
                ],
            },
        ),
        (
            "environment self-review",
            {
                **protected_environment,
                "protection_rules": [
                    {
                        **protected_environment["protection_rules"][0],
                        "prevent_self_review": False,
                    }
                ],
            },
        ),
        (
            "environment administrator bypass",
            {
                **protected_environment,
                "can_admins_bypass": True,
            },
        ),
        (
            "environment unprotected branch",
            {
                **protected_environment,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
        ),
    ):
        try:
            validate_environment_document(mutation, "production")
        except PolicyError:
            pass
        else:
            raise PolicyError(f"negative {mutation_name} regression passed")
    candidate_document = {
        "schema_version": CANDIDATE_SCHEMA,
        "template": False,
        "release_id": "release-test-001",
        "controller_sha": "1" * 40,
        "source_lock_sha": "2" * 40,
        "runtime_candidate_sha256": "3" * 64,
        "safety": {key: False for key in CANDIDATE_SAFETY_KEYS},
        "components": [
            {
                "repository": repository,
                "source_sha": "1" * 40 if repository == CONTROLLER_REPOSITORY else "4" * 40,
                "contract_sha256": "5" * 64,
                "images": [],
                "previous_images": [],
                "enabled": True,
            }
            for repository in sorted(CATALOG_REPOSITORIES)
        ],
    }
    candidate_raw = json.dumps(candidate_document, sort_keys=True).encode()
    candidate_hash = hashlib.sha256(candidate_raw).hexdigest()
    validate_candidate_document(
        candidate_raw,
        candidate_hash,
        "release-test-001",
        "appolon1908-hue/Infustruction-repo",
        "4" * 40,
        "5" * 64,
        [],
        [],
    )
    try:
        validate_candidate_document(
            candidate_raw,
            "6" * 64,
            "release-test-001",
            "appolon1908-hue/Infustruction-repo",
            "4" * 40,
            "5" * 64,
            [],
            [],
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("negative candidate hash regression passed")
    validate_phase_blockers(["runtime recovery evidence is missing"], "plan")
    try:
        validate_phase_blockers(["runtime recovery evidence is missing"], "staging")
    except PolicyError:
        pass
    else:
        raise PolicyError("negative unresolved blocker regression passed")
    print("RELEASE_INTENT_SELF_TEST=PASS")
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            raise SystemExit(self_test())
        if sys.argv[1:] == ["--recheck-protected-gates"]:
            raise SystemExit(recheck_protected_gates())
        require(not sys.argv[1:], "unsupported arguments")
        raise SystemExit(main())
    except PolicyError as error:
        raise SystemExit(str(error)) from error
