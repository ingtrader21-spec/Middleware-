#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import NoReturn

MAX_SECRET_BYTES = 4_096


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def protected_secret(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("invalid secret reference")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("invalid secret reference")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("secret file permissions are too broad")
        raw = os.read(descriptor, MAX_SECRET_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAX_SECRET_BYTES:
        fail("invalid secret length")
    if any(byte < 0x20 or byte == 0x7F for byte in raw):
        fail("invalid secret")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("invalid secret encoding")


def prepare_output_directory(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        fail("unsafe output")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        fail("output directory permissions are too broad")


def atomic_write(directory: Path, name: str, data: str) -> None:
    target = directory / name
    if target.is_symlink() or (target.exists() and not target.is_file()):
        fail("unsafe target")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{name}.",
        dir=directory,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        fsync_dir(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)

    secret = protected_secret(args.secret_file)
    base = Path(__file__).resolve().parent
    output = args.output_dir
    prepare_output_directory(output)
    try:
        template = (base / "templates/pjsip-6198.conf.in").read_text(
            encoding="utf-8"
        )
        extensions = (base / "templates/extensions-6198.conf").read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError):
        fail("fixture template is unreadable")
    if template.count("@SIP_SECRET@") != 1:
        fail("template placeholder mismatch")

    files = {
        "pjsip-6198.conf": template.replace("@SIP_SECRET@", secret),
        "extensions-6198.conf": extensions,
    }
    redacted = files["pjsip-6198.conf"].replace(secret, "<redacted>")
    structure = {
        "pjsip_sha256": hashlib.sha256(redacted.encode()).hexdigest(),
        "dialplan_sha256": hashlib.sha256(extensions.encode()).hexdigest(),
    }
    files["redacted-structure.json"] = (
        json.dumps(structure, sort_keys=True) + "\n"
    )
    for name, data in files.items():
        atomic_write(output, name, data)
    print("render complete; secret redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
