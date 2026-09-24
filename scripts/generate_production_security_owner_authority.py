#!/usr/bin/env python3
"""Generate a finite authority after an independent protected-environment approval."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--approver", required=True)
    parser.add_argument("--approval-record", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)  # noqa: UP017
    expires = now + timedelta(days=7)
    stamp = now.isoformat().replace("+00:00", "Z")
    expires_stamp = expires.isoformat().replace("+00:00", "Z")
    document = {
        "schema_version": "codestra.security-owner.production-authority.v1",
        "company": "Codestra LLC",
        "authority_id": f"codestra-production-{args.source_sha[:12]}-{args.approval_record}",
        "role": "Security Owner",
        "authorized_identity": f"https://github.com/{args.approver}",
        "github_identity": args.approver,
        "authority_reference": f"github-environment-review:{args.approval_record}",
        "approved_scopes": [
            "server_a_production_release",
            "production_deployment",
            "external_delivery_synthetic_only",
        ],
        "prohibited_scopes": [
            "production_activation", "canary_activation", "server_b_access",
            "customer_data", "unrestricted_n8n_activation", "external_delivery_general",
        ],
        "source_sha": args.source_sha,
        "communications": {"calls": False, "sms": False, "email": False, "callbacks": False},
        "issued_utc": stamp,
        "not_before_utc": stamp,
        "expires_utc": expires_stamp,
        "approving_authority": "Codestra LLC protected environment security-owner-authority",
        "signature_method": "sigstore-keyless-oidc",
        "signature_key_id": "https://token.actions.githubusercontent.com",
        "detached_signature_path": "security-owner-authority.sigstore.json",
    }
    canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    document["document_sha256"] = hashlib.sha256(canonical).hexdigest()
    args.output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
