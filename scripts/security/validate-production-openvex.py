#!/usr/bin/env python3
"""Validate an exact-source, exact-image production OpenVEX document."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


class ValidationError(ValueError):
    pass


def load(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("OpenVEX must be an object")
    return value


def validate(document: dict[str, Any], *, source_sha: str, image_digest: str) -> None:
    if not SHA.fullmatch(source_sha) or not DIGEST.fullmatch(image_digest):
        raise ValidationError("invalid expected source SHA or image digest")
    if document.get("@context") != "https://openvex.dev/ns/v0.2.0":
        raise ValidationError("unsupported OpenVEX context")
    for field in ("@id", "author", "timestamp", "last_updated"):
        if not isinstance(document.get(field), str) or not document[field].strip():
            raise ValidationError(f"missing {field}")
    if document.get("version") != 1:
        raise ValidationError("unsupported OpenVEX version")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("source_sha") != source_sha:
        raise ValidationError("source SHA binding mismatch")
    if metadata.get("image_digest") != image_digest:
        raise ValidationError("metadata image digest mismatch")
    statements = document.get("statements")
    if not isinstance(statements, list) or not statements:
        raise ValidationError("at least one disposition is required")
    encoded_digest = image_digest.replace(":", "%3A")
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("status") not in STATUSES:
            raise ValidationError("invalid disposition status")
        vulnerability = statement.get("vulnerability")
        if not isinstance(vulnerability, dict) or not vulnerability.get("name"):
            raise ValidationError("missing vulnerability identity")
        products = statement.get("products")
        if not isinstance(products, list) or not products:
            raise ValidationError("disposition has no products")
        for product in products:
            product_id = product.get("@id") if isinstance(product, dict) else None
            if not isinstance(product_id, str) or encoded_digest not in product_id:
                raise ValidationError("product is not bound to the exact image digest")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openvex", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    try:
        validate(load(args.openvex), source_sha=args.source_sha, image_digest=args.image_digest)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise SystemExit(f"production OpenVEX validation failed: {exc}") from exc
    print("PRODUCTION_OPENVEX_VALIDATION_GATE=PASS")


if __name__ == "__main__":
    main()
