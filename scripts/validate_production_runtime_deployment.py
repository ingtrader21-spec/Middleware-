#!/usr/bin/env python3
"""Validate the fail-closed Middleware production canary contract and evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "deploy/production/server-command-contract.v1.json"
COMPOSE_PATH = ROOT / "deploy/production/compose.canary.yaml"
CONTROLLER_PATH = ROOT / "deploy/production/server/codestra-middleware-deploy"
BACKUP_PATH = ROOT / "deploy/production/server/codestra-middleware-backup"
INSTALL_PATH = ROOT / "deploy/production/server/install-restricted-command.sh"
WORKFLOW_PATH = ROOT / ".github/workflows/production-runtime-certification.yml"

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REFERENCE = re.compile(
    r"^ghcr\.io/ingtrader21-spec/codestra-middleware@sha256:[0-9a-f]{64}$"
)
RELEASE_ID = re.compile(r"^[0-9a-f]{12}-[0-9a-f]{12}$")


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_runtime_workflow(workflow: str) -> None:
    """Require the repository-local runtime workflow to remain inert.

    Middleware supplies signed source/image evidence.  It is not a runtime
    mutation authority, so retaining the historical certification procedure is
    safe only while its sole job is unconditionally disabled.
    """
    require(
        workflow.count("\njobs:\n") == 1,
        "runtime workflow must define one jobs section",
    )
    jobs_section = workflow.partition("\njobs:\n")[2]
    jobs = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs_section)
    require(
        jobs == ["certify"],
        "runtime workflow must contain only the disabled certify job",
    )
    require(
        re.search(r"(?m)^    if:\s*\$\{\{\s*false\s*\}\}\s*$", workflow) is not None,
        "runtime workflow certify job must remain unconditionally disabled",
    )
    for item in (
        "RUNTIME_MUTATION_DISABLED=true",
        "Infustruction-repo is the sole infrastructure runtime authority.",
        "environment: middleware-runtime-certification",
        "MIDDLEWARE_DEPLOY_HOST",
        "MIDDLEWARE_DEPLOY_SSH_KEY",
        "MIDDLEWARE_DEPLOY_HOST_KEY",
        "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=",
        "ssh_options=(",
        "scp_options=(",
        '-p "$DEPLOY_PORT"',
        '-P "$DEPLOY_PORT"',
        'scp "${scp_options[@]}" "$BUNDLE_ARCHIVE"',
        'scp "${scp_options[@]}" "$remote:$evidence_remote"',
        "codestra-middleware-deploy",
    ):
        require(item in workflow, f"workflow requirement missing: {item}")
    for item in (
        "ssh-keyscan",
        "appleboy/ssh-action",
        "StrictHostKeyChecking=no",
        'scp "${ssh_options[@]}"',
    ):
        require(item not in workflow, f"workflow contains unsafe SSH behavior: {item}")
    uses = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", workflow)
    require(bool(uses), "workflow must use pinned actions")
    for action in uses:
        require(
            re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) is not None,
            f"action is not commit-pinned: {action}",
        )


def load_contract() -> dict[str, object]:
    value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "contract must be an object")
    require(value.get("schema_version") == "1.0", "contract schema mismatch")
    return value


def validate_source(root: Path = ROOT) -> None:
    global \
        CONTRACT_PATH, \
        COMPOSE_PATH, \
        CONTROLLER_PATH, \
        BACKUP_PATH, \
        INSTALL_PATH, \
        WORKFLOW_PATH
    if root != ROOT:
        CONTRACT_PATH = root / "deploy/production/server-command-contract.v1.json"
        COMPOSE_PATH = root / "deploy/production/compose.canary.yaml"
        CONTROLLER_PATH = root / "deploy/production/server/codestra-middleware-deploy"
        BACKUP_PATH = root / "deploy/production/server/codestra-middleware-backup"
        INSTALL_PATH = root / "deploy/production/server/install-restricted-command.sh"
        WORKFLOW_PATH = root / ".github/workflows/middleware-runtime-certification.yml"
    for path in (
        CONTRACT_PATH,
        COMPOSE_PATH,
        CONTROLLER_PATH,
        BACKUP_PATH,
        INSTALL_PATH,
        WORKFLOW_PATH,
    ):
        require(path.is_file(), f"required production deployment file missing: {path}")

    contract = load_contract()
    deployment = contract.get("deployment")
    safety = contract.get("safety")
    response = contract.get("response")
    if not isinstance(deployment, dict):
        raise ValidationError("deployment contract section missing")
    if not isinstance(safety, dict):
        raise ValidationError("safety contract section missing")
    if not isinstance(response, dict):
        raise ValidationError("response contract section missing")
    require(
        deployment.get("command") == "/usr/local/sbin/codestra-middleware-deploy",
        "command authority drift",
    )
    require(
        deployment.get("expected_host") == "65.109.65.169", "server authority drift"
    )
    require(
        deployment.get("restricted_user") == "middleware-deploy",
        "restricted user drift",
    )
    require(deployment.get("mode") == "READ_ONLY_CANARY", "deployment mode drift")
    require(deployment.get("source_ref") == "refs/heads/main", "source ref drift")
    require(
        deployment.get("schema_head") == "0069_agent_provisioning_rls",
        "schema head drift",
    )
    for key in (
        "broad_compose_down_allowed",
        "business_writes_enabled",
        "docker_prune_allowed",
        "external_effects_enabled",
        "force_push_allowed",
        "gateway_exposure_allowed",
        "mutable_image_tags_allowed",
        "outbox_worker_started",
        "server_source_writes_to_github",
        "ssh_configuration_changes_allowed",
        "unrestricted_sudo_allowed",
    ):
        require(safety.get(key) is False, f"unsafe contract setting: {key}")
    require(
        safety.get("service_scoped_compose_only") is True,
        "service-scoped Compose is required",
    )
    require(
        safety.get("production_dialing") == "DISABLED",
        "production dialing must be disabled",
    )

    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    for item in (
        "name: codestra-middleware-production-canary",
        "middleware-api-canary:",
        "middleware-migrate-canary:",
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "pull_policy: never",
        "com.codestra.gateway.exposure: none",
        'OUTBOX_DISPATCH_ENABLED: "false"',
        "PRODUCTION_DIALING: DISABLED",
    ):
        require(item in compose, f"compose requirement missing: {item}")
    for pattern in (
        r"(?m)^\s*ports:\s*$",
        r"privileged:\s*true",
        r"network_mode:\s*host",
        r"pid:\s*host",
        r"/var/run/docker\.sock",
        r"image:\s*[^\n]*:latest(?:\s|$)",
    ):
        require(
            re.search(pattern, compose, re.IGNORECASE) is None,
            f"unsafe compose pattern: {pattern}",
        )

    controller = CONTROLLER_PATH.read_text(encoding="utf-8")
    for item in (
        "--source-sha",
        "--image-reference",
        "--release-run-id",
        "--release-id",
        "--bundle-path",
        "--bundle-sha256",
        "--controller-sha256",
        "--mode",
        "--registry-token-stdin",
        "READ_ONLY_CANARY",
        "business_data_changed_during_canary",
        "ROLLBACK_STATUS=PASS",
        "EXTERNAL_EFFECTS_ENABLED=NONE",
        "CALLS_PLACED=0",
        "RUNTIME_SCHEMA_VERIFIED=PASS",
        "FROM public.alembic_version",
        "actual_alembic_head_mismatch",
        "FROM public.middleware_automation_schema_migrations",
        "automation_schema_head_mismatch",
        "platform_schema_incomplete",
        "GATEWAY_EXPOSURE=NONE",
    ):
        require(item in controller, f"controller requirement missing: {item}")
    forbidden_shell = (
        "docker compose down",
        "docker system prune",
        "docker volume prune",
        "docker network prune",
        "authorized_keys",
        "sshd_config",
        "ssh-keygen",
        "iptables ",
        "ufw ",
        "git push",
    )
    lowered_controller = controller.lower()
    for item in forbidden_shell:
        require(
            item not in lowered_controller,
            f"controller contains forbidden operation: {item}",
        )

    backup = BACKUP_PATH.read_text(encoding="utf-8")
    for item in ("pg_dump", "pg_restore", "createdb", "dropdb", "RESTORE_STATUS=PASS"):
        require(item in backup, f"backup/restore requirement missing: {item}")

    install = INSTALL_PATH.read_text(encoding="utf-8")
    require(
        "SSH_CONFIGURATION_CHANGED=NO" in install,
        "installer must report no SSH changes",
    )
    for item in ("authorized_keys", "sshd_config", "ssh-keygen"):
        require(item not in install.lower(), f"installer contains SSH mutation: {item}")

    validate_runtime_workflow(WORKFLOW_PATH.read_text(encoding="utf-8"))


def parse_response(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        require("=" in raw, f"invalid response line {number}")
        key, value = raw.split("=", 1)
        require(
            re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is not None,
            f"invalid response key: {key}",
        )
        require(key not in values, f"duplicate response key: {key}")
        require(
            "\n" not in value and "\r" not in value, f"invalid response value: {key}"
        )
        values[key] = value
    return values


def validate_response(
    path: Path,
    *,
    source_sha: str,
    image_reference: str,
    release_run_id: str,
    release_id: str,
) -> dict[str, str]:
    require(SHA40.fullmatch(source_sha) is not None, "expected source SHA invalid")
    require(
        IMAGE_REFERENCE.fullmatch(image_reference) is not None,
        "expected image reference invalid",
    )
    require(
        re.fullmatch(r"[1-9][0-9]{5,19}", release_run_id) is not None,
        "expected release run ID invalid",
    )
    require(RELEASE_ID.fullmatch(release_id) is not None, "expected release ID invalid")
    values = parse_response(path)
    contract = load_contract()
    response = contract["response"]
    assert isinstance(response, dict)
    required_keys = response["required_keys"]
    fixed = response["fixed_values"]
    assert isinstance(required_keys, list) and isinstance(fixed, dict)
    missing = [key for key in required_keys if key not in values]
    require(not missing, "response missing keys: " + ",".join(missing))
    for key, expected in fixed.items():
        require(values.get(key) == expected, f"response fixed value mismatch: {key}")
    expected_dynamic = {
        "SOURCE_SHA": source_sha,
        "IMAGE_REFERENCE": image_reference,
        "IMAGE_DIGEST": image_reference.rsplit("@", 1)[1],
        "RELEASE_RUN_ID": release_run_id,
        "RELEASE_ID": release_id,
        "VERSION_SOURCE_SHA": source_sha,
        "VERSION_IMAGE_DIGEST": image_reference.rsplit("@", 1)[1],
        "VERSION_SCHEMA_HEAD": "0069_agent_provisioning_rls",
    }
    for key, expected in expected_dynamic.items():
        require(values.get(key) == expected, f"response dynamic value mismatch: {key}")
    require(
        DIGEST.fullmatch(values["BACKUP_SHA256"]) is not None, "backup digest invalid"
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", values["CONFIGURATION_CHECKSUM"]) is not None,
        "configuration checksum invalid",
    )
    require(values["ROLLBACK_RTO_SECONDS"].isdigit(), "rollback RTO invalid")
    require(
        values["OBSERVATION_SECONDS"].isdigit()
        and int(values["OBSERVATION_SECONDS"]) >= 30,
        "observation window invalid",
    )
    evidence_path = values["EVIDENCE_BUNDLE_PATH"]
    require(
        evidence_path.startswith("/home/middleware-deploy/incoming/"),
        "unsafe evidence path",
    )
    require(".." not in evidence_path, "unsafe evidence traversal")
    require(
        DIGEST.fullmatch(values["EVIDENCE_BUNDLE_SHA256"]) is not None,
        "evidence digest invalid",
    )
    return values


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    require(0 < len(members) <= 1000, "evidence archive member count invalid")
    for member in members:
        relative = PurePosixPath(member.name)
        require(
            not relative.is_absolute() and ".." not in relative.parts,
            "unsafe evidence path",
        )
        require(
            member.isdir() or member.isfile(),
            "evidence links and special files are forbidden",
        )
    return members


def validate_evidence(
    archive_path: Path,
    *,
    expected_sha256: str,
    source_sha: str,
    image_reference: str,
    release_run_id: str,
    release_id: str,
) -> None:
    require(archive_path.is_file(), "evidence archive missing")
    actual = "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest()
    require(actual == expected_sha256, "evidence archive checksum mismatch")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = _safe_members(archive)
        result_members = [
            item for item in members if PurePosixPath(item.name).name == "result.json"
        ]
        require(len(result_members) == 1, "evidence result.json missing or duplicated")
        handle = archive.extractfile(result_members[0])
        if handle is None:
            raise ValidationError("evidence result.json unreadable")
        value = json.load(handle)
    require(
        value.get("schema_version") == "1.0" and value.get("result") == "PASS",
        "evidence result is not PASS",
    )
    require(value.get("source_sha") == source_sha, "evidence source SHA mismatch")
    require(value.get("image_reference") == image_reference, "evidence image mismatch")
    require(
        str(value.get("release_run_id")) == release_run_id,
        "evidence release run mismatch",
    )
    require(value.get("release_id") == release_id, "evidence release ID mismatch")
    runtime = value.get("runtime")
    rollback = value.get("rollback")
    backup = value.get("backup")
    require(isinstance(runtime, Mapping), "evidence runtime section missing")
    require(isinstance(rollback, Mapping), "evidence rollback section missing")
    require(isinstance(backup, Mapping), "evidence backup section missing")
    require(
        runtime.get("health")
        == runtime.get("readiness")
        == runtime.get("version")
        == runtime.get("capabilities")
        == "PASS",
        "runtime evidence incomplete",
    )
    require(
        runtime.get("external_effects_enabled") == "NONE",
        "external effects were enabled",
    )
    require(
        runtime.get("business_writes_enabled") is False
        and runtime.get("calls_placed") == 0,
        "runtime effect counters invalid",
    )
    require(
        runtime.get("gateway_exposure") == "NONE", "gateway exposure is not isolated"
    )
    require(
        backup.get("status") == "PASS" and backup.get("restore_rehearsal") == "PASS",
        "backup/restore evidence incomplete",
    )
    require(rollback.get("status") == "PASS", "rollback evidence incomplete")
    require(value.get("data_integrity") == "PASS", "data integrity evidence incomplete")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("source")
    response = sub.add_parser("response")
    evidence = sub.add_parser("evidence")
    for command in (response, evidence):
        command.add_argument("--source-sha", required=True)
        command.add_argument("--image-reference", required=True)
        command.add_argument("--release-run-id", required=True)
        command.add_argument("--release-id", required=True)
    response.add_argument("--file", type=Path, required=True)
    evidence.add_argument("--archive", type=Path, required=True)
    evidence.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.mode == "source":
        validate_source()
        print("PRODUCTION_RUNTIME_DEPLOYMENT_SOURCE=PASS")
    elif args.mode == "response":
        validate_response(
            args.file,
            source_sha=args.source_sha,
            image_reference=args.image_reference,
            release_run_id=args.release_run_id,
            release_id=args.release_id,
        )
        print("PRODUCTION_RUNTIME_DEPLOYMENT_RESPONSE=PASS")
    else:
        validate_evidence(
            args.archive,
            expected_sha256=args.sha256,
            source_sha=args.source_sha,
            image_reference=args.image_reference,
            release_run_id=args.release_run_id,
            release_id=args.release_id,
        )
        print("PRODUCTION_RUNTIME_DEPLOYMENT_EVIDENCE=PASS")


if __name__ == "__main__":
    main()
