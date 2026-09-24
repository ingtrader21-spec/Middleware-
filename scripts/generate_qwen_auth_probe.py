#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import secrets
import subprocess
import time
import uuid
from pathlib import Path

PATH = "/internal/api/v1/ai/auth/verify"
SERVICE_ID = "qwen-ai-01"
HMAC_KEY_ID = "qwen-ai-01-hmac-20260804-01"
SERVER_NAME = "middleware.internal.codestra.agency"
PRIVATE_IP = "10.40.0.1"


def protected_file(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} file is unavailable")
    if path.stat().st_mode & 0o077:
        raise SystemExit(f"{label} file permissions are unsafe")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--ca-chain", required=True)
    parser.add_argument("--hmac-secret", required=True)
    parser.add_argument("--service-id", choices=[SERVICE_ID], default=SERVICE_ID)
    parser.add_argument("--hmac-key-id", choices=[HMAC_KEY_ID], default=HMAC_KEY_ID)
    parser.add_argument("--server-name", choices=[SERVER_NAME], default=SERVER_NAME)
    parser.add_argument("--private-ip", choices=[PRIVATE_IP], default=PRIVATE_IP)
    args = parser.parse_args()

    certificate = protected_file(args.certificate, "certificate")
    private_key = protected_file(args.private_key, "private key")
    ca_chain = protected_file(args.ca_chain, "CA chain")
    secret_file = protected_file(args.hmac_secret, "HMAC secret")
    secret = secret_file.read_bytes().strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", secret):
        raise SystemExit("HMAC secret file is invalid")

    body = b"{}"
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    digest = hashlib.sha256(body).hexdigest()
    canonical = (
        f"POST\n{PATH}\n{args.service_id}\n{timestamp}\n{nonce}\n{digest}"
    ).encode("ascii")
    signature = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    correlation = f"qwen-auth-{uuid.uuid4()}"
    url = f"https://{args.server_name}{PATH}"
    command = [
        "/usr/bin/curl",
        "--fail-with-body",
        "--silent",
        "--show-error",
        "--resolve",
        f"{args.server_name}:443:{args.private_ip}",
        "--cacert",
        str(ca_chain),
        "--cert",
        str(certificate),
        "--key",
        str(private_key),
        "--request",
        "POST",
        "--header",
        f"X-Service-ID: {args.service_id}",
        "--header",
        f"X-HMAC-Key-ID: {args.hmac_key_id}",
        "--header",
        f"X-Timestamp: {timestamp}",
        "--header",
        f"X-Nonce: {nonce}",
        "--header",
        f"X-Body-SHA256: {digest}",
        "--header",
        f"X-Signature: {signature}",
        "--header",
        f"X-Correlation-ID: {correlation}",
        "--header",
        "Content-Type: application/json",
        "--data-binary",
        "{}",
        url,
    ]
    # The absolute executable and argument vector are fixed; every configurable
    # identity/network value is constrained above and no shell is involved.
    return subprocess.run(
        command,  # nosemgrep: dangerous-subprocess-use-tainted-env-args
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
