#!/usr/bin/env python3
"""Fail-closed check that Middleware carries the exact OpenBao secret-reference contract.

Middleware stores secret references, never values. The v1 schema is owned by
``appolon1908-hue/Codestra-OpenBao`` (``contracts/secret-reference.v1.schema.json``)
and vendored under ``contracts/secrets/`` with a canonical sha256 pin. This
script proves the vendored copy matches its pin, that the model in
``app.secret_reference`` enforces the schema's forbidden keys, and, when an
OpenBao checkout is given, that the vendored bytes equal the authority's.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.secret_reference import (  # noqa: E402
    PIN_PATH,
    SecretReference,
    SecretReferenceError,
    canonical_digest,
    forbidden_keys,
    schema,
)

POISON = (
    "value",
    "password",
    "token",
    "private_key",
    "client_secret",
    "secret",
    "root_token",
)


def openbao_repository(explicit: str | None) -> Path | None:
    candidate = explicit or os.environ.get("OPENBAO_REPO")
    if not candidate:
        return None
    path = Path(candidate) / "contracts" / "secret-reference.v1.schema.json"
    if not path.is_file():
        raise SecretReferenceError(
            f"OpenBao checkout has no secret-reference schema: {candidate}"
        )
    return Path(candidate)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--openbao-repo")
    parser.add_argument("--require-cross-check", action="store_true")
    args = parser.parse_args()
    try:
        document = schema()
        pinned = PIN_PATH.read_text(encoding="utf-8").strip()
        if canonical_digest(document) != pinned:
            raise SecretReferenceError("vendored schema does not match its pin")
        if set(document["x-codestra-forbidden-keys"]) != set(forbidden_keys()):
            raise SecretReferenceError(
                "forbidden-key list drifted between schema and model"
            )
        base = {
            "environment": "staging",
            "service_id": "middleware",
            "secret_ref": "codestra/staging/middleware/api/database",
            "secret_class": "database_credentials",
        }
        SecretReference.model_validate(base)
        for key in POISON:
            try:
                SecretReference.model_validate({**base, key: "x"})
            except (SecretReferenceError, ValueError):
                continue
            raise SecretReferenceError(f"model accepted a value-bearing key: {key}")
        for bad in (
            {**base, "environment": "production"},
            {**base, "secret_ref": "codestra/staging/middleware/api/*"},
            {**base, "reference_uri": "openbao://codestra/staging/other"},
            {**base, "secret_class": "anything"},
        ):
            try:
                SecretReference.model_validate(bad)
            except (SecretReferenceError, ValueError):
                continue
            raise SecretReferenceError(f"model accepted an invalid reference: {bad}")
        repo = openbao_repository(args.openbao_repo)
        if repo is None:
            if args.require_cross_check:
                raise SecretReferenceError(
                    "OpenBao checkout is required for the cross-check"
                )
            cross = "SKIPPED_NO_OPENBAO_CHECKOUT"
        else:
            authority = json.loads(
                (repo / "contracts" / "secret-reference.v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            if canonical_digest(authority) != pinned:
                raise SecretReferenceError(
                    "OpenBao schema differs from the vendored, pinned copy"
                )
            cross = "PASS"
    except (SecretReferenceError, OSError, json.JSONDecodeError) as exc:
        print(f"SECRET_REFERENCE_CONTRACT=FAIL {exc}", file=sys.stderr)
        return 1
    print("SECRET_REFERENCE_CONTRACT=PASS")
    print(f"SECRET_REFERENCE_SCHEMA_SHA256={pinned}")
    print(f"SECRET_REFERENCE_CROSS_CHECK={cross}")
    print("SECRET_VALUES_STORED_BY_MIDDLEWARE=NEVER")
    return 0


if __name__ == "__main__":
    sys.exit(main())
