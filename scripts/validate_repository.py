#!/usr/bin/env python3
"""Fail-closed bootstrap validation for the Codestra middleware repository.

This validator is intentionally dependency-free so it can run before the live
middleware's package manager and lock files are imported. It is a guardrail,
not a replacement for a dedicated secret scanner, SAST, dependency audit,
container scan, or application integration tests.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 10 * 1024 * 1024

REQUIRED_FILES = (
    Path("README.md"),
    Path(".gitignore"),
    Path(".dockerignore"),
    Path("config/preproduction-safety.env.example"),
    Path("config/provider-operation-policy.json"),
    Path("config/middleware-forward-release-authority.v1.json"),
)

FORBIDDEN_TOP_LEVEL_DIRECTORIES = {
    "backups",
    "credentials",
    "private-evidence",
    "runtime",
    "secrets",
}

FORBIDDEN_SUFFIXES = {
    ".aof",
    ".backup",
    ".dump",
    ".har",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pcap",
    ".pfx",
    ".rdb",
    ".sqlite",
    ".sqlite3",
    ".trace",
}

SECRET_PATTERNS = {
    "private key material": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "GitHub fine-grained token": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
}

EXPECTED_SAFETY_VALUES = {
    "APP_ENV": "staging",
    "SEND_EVENTS": "false",
    "ENABLE_EXTERNAL_DELIVERY": "false",
    "LIVE_WRITE": "false",
    "LIVE_WRITES": "false",
    "ODOO_WRITE": "false",
    "CALLBACK_DISPATCH": "false",
    "N8N_DELIVERY_ENABLED": "false",
    "VICIDIAL_WRITES_ENABLED": "false",
    "EXTERNAL_DIAL_ENABLED": "false",
    "PRODUCTION_CALLBACKS_ENABLED": "false",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED": "false",
    "PRODUCTION_DIALING": "DISABLED",
    "LIVE_SMS_DELIVERY": "false",
    "LIVE_EMAIL_DELIVERY": "false",
    "UNRESTRICTED_CRAWLING": "false",
}

ACTION_REF_RE = re.compile(
    r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s*#.*)?$", re.MULTILINE
)
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def is_allowed_env_example(path: Path) -> bool:
    name = path.name.lower()
    return name == ".env.example" or name.endswith(".env.example")


def is_live_env_file(path: Path) -> bool:
    name = path.name.lower()
    looks_like_env = (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith(".env")
        or ".env." in name
    )
    return looks_like_env and not is_allowed_env_example(path)


def iter_repository_files() -> list[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"cannot enumerate repository files with Git: {exc}") from exc

    files: list[Path] = []
    for raw_relative in result.stdout.split(b"\0"):
        if not raw_relative:
            continue
        relative = Path(raw_relative.decode("utf-8", errors="strict"))
        path = ROOT / relative
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files)


def validate_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required bootstrap file: {relative}")


def validate_paths(files: list[Path], errors: list[str]) -> None:
    for path in files:
        relative = path.relative_to(ROOT)

        if path.is_symlink():
            try:
                target = path.resolve(strict=False)
                target.relative_to(ROOT)
            except ValueError:
                errors.append(f"symlink escapes repository: {relative} -> {path.readlink()}")

        if relative.parts and relative.parts[0] in FORBIDDEN_TOP_LEVEL_DIRECTORIES:
            errors.append(f"forbidden top-level runtime/secret path: {relative}")

        if is_live_env_file(path):
            errors.append(f"live environment file must not be committed: {relative}")

        lower_name = path.name.lower()
        if any(lower_name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            errors.append(f"forbidden secret/runtime file type: {relative}")

        try:
            size = path.lstat().st_size
        except OSError as exc:
            errors.append(f"cannot stat {relative}: {exc}")
            continue
        if size > MAX_FILE_BYTES:
            errors.append(
                f"file exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB bootstrap limit: "
                f"{relative} ({size} bytes)"
            )


def validate_file_contents(files: list[Path], errors: list[str]) -> None:
    for path in files:
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot read {relative}: {exc}")
            continue

        if b"\x00" in data:
            continue

        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(data):
                errors.append(f"possible {label} committed in: {relative}")


def parse_env_example(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"line {line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"line {line_number} has invalid variable name {key!r}")
        if key in values:
            raise ValueError(f"line {line_number} duplicates variable {key}")
        values[key] = value.strip()
    return values


def validate_safety_baseline(errors: list[str]) -> None:
    path = ROOT / "config/preproduction-safety.env.example"
    if not path.is_file():
        return
    try:
        values = parse_env_example(path)
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(f"invalid preproduction safety baseline: {exc}")
        return

    for key, expected in EXPECTED_SAFETY_VALUES.items():
        actual = values.get(key)
        if actual != expected:
            errors.append(
                f"unsafe or missing baseline value: {key}={actual!r}; "
                f"expected {expected!r}"
            )


def validate_workflow_pinning(errors: list[str]) -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        errors.append("missing .github/workflows directory")
        return

    workflow_files = sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in workflow_dir.glob(pattern)
    )
    if not workflow_files:
        errors.append("no GitHub Actions workflow is present")
        return

    for path in workflow_files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read workflow {path.relative_to(ROOT)}: {exc}")
            continue

        for match in ACTION_REF_RE.finditer(text):
            action = match.group(1).strip("\"'")
            if action.startswith("./"):
                continue
            if action.startswith("docker://"):
                image_ref = action.removeprefix("docker://")
                if "@sha256:" not in image_ref:
                    errors.append(
                        f"container action is not digest-pinned in "
                        f"{path.relative_to(ROOT)}: {action}"
                    )
                continue
            if "@" not in action:
                errors.append(
                    f"action has no immutable ref in {path.relative_to(ROOT)}: {action}"
                )
                continue
            _, ref = action.rsplit("@", 1)
            if not FULL_SHA_RE.fullmatch(ref):
                errors.append(
                    f"action is not pinned to a 40-character commit SHA in "
                    f"{path.relative_to(ROOT)}: {action}"
                )


def _migration_assignment(path: Path, name: str) -> str | tuple[str, ...] | None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        if node.value is None:
            raise ValueError(f"{name} assignment has no value")
        value = ast.literal_eval(node.value)
        if value is None or isinstance(value, str):
            return value
        if isinstance(value, (tuple, list)) and all(isinstance(item, str) for item in value):
            return tuple(value)
        raise ValueError(f"{name} must be a string, string sequence, or None")
    raise ValueError(f"missing {name} assignment")


def validate_production_migration_head(errors: list[str]) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.production_migration_authority import validate_authority
    try:
        validate_authority(ROOT)
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, SyntaxError) as exc:
        errors.append(str(exc))


def main() -> int:
    errors: list[str] = []
    try:
        files = iter_repository_files()
    except (RuntimeError, UnicodeError) as exc:
        print(f"Middleware repository validation failed:\n  - {exc}", file=sys.stderr)
        return 1

    validate_required_files(errors)
    validate_paths(files, errors)
    validate_file_contents(files, errors)
    validate_safety_baseline(errors)
    validate_workflow_pinning(errors)
    validate_production_migration_head(errors)

    if errors:
        print("Middleware repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Middleware repository validation passed for {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
