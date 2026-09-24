"""Recover a SLSA predicate from an already authenticated immutable release.

The caller must first verify the manifest Sigstore bundle and the registry
attestations. This script checks their content bindings; it does not authenticate
Cosign output on its own. No rebuild or new build claim is made.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.release_manifest import load_manifest, validate_manifest
else:
    try:
        from scripts.release_manifest import load_manifest, validate_manifest
    except ModuleNotFoundError:
        from release_manifest import load_manifest, validate_manifest

SOURCE = "29b25cba8302cd15ef4d87b68f501da6347f2f17"
DIGEST = "sha256:0f5a5b3b1c8166d6509b228541bee01533f5feb1dbef24ed2d241194ba610802"
REPOSITORY = "ghcr.io/appolon1908-hue/codestra-middleware"
BUILDER = (
    "https://github.com/appolon1908-hue/Middleware-/"
    ".github/workflows/release.yml@refs/heads/main"
)


def check_attestation(path: Path, predicate_type: str, predicate: dict) -> None:
    text = path.read_text().strip()
    try:
        parsed = json.loads(text)
        documents = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        documents = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not documents:
        raise ValueError("empty verified attestations")
    for document in documents:
        statement = json.loads(base64.b64decode(document["payload"], validate=True))
        if (
            statement.get("_type") != "https://in-toto.io/Statement/v0.1"
            or statement.get("predicateType") != predicate_type
            or statement.get("subject") != [{
                "name": REPOSITORY,
                "digest": {"sha256": DIGEST.removeprefix("sha256:")},
            }]
            or statement.get("predicate") != predicate
        ):
            raise ValueError("verified attestation differs from pinned release")


def recover(evidence: Path, sbom_verification: Path) -> dict:
    manifest = load_manifest(evidence / "release-manifest.v1.json")
    validate_manifest(manifest, expected_source_sha=SOURCE, expected_image_digest=DIGEST)
    if manifest["build"]["run_id"] != 33922375053 or manifest["build"]["run_attempt"] != 1:
        raise ValueError("unexpected original release run")
    for key in ("sbom", "vulnerability_report"):
        entry = manifest["artifacts"][key]
        path = evidence / entry["path"]
        if path.resolve().parent != evidence.resolve():
            raise ValueError("evidence path escapes release directory")
        if "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("original release evidence hash mismatch")
    sbom = json.loads((evidence / manifest["artifacts"]["sbom"]["path"]).read_text())
    check_attestation(sbom_verification, "https://spdx.dev/Document", sbom)
    return {
        "buildDefinition": {
            "buildType": "https://codestra.example/buildtypes/exact-main-middleware-production/v1",
            "externalParameters": {"sourceSha": SOURCE, "platform": "linux/amd64"},
            "resolvedDependencies": [{
                "uri": f"git+https://github.com/appolon1908-hue/Middleware-@{SOURCE}",
                "digest": {"gitCommit": SOURCE},
            }],
        },
        "runDetails": {"builder": {"id": BUILDER}},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--sbom-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provenance-verification", type=Path)
    args = parser.parse_args()
    predicate = recover(args.evidence, args.sbom_verification)
    if args.provenance_verification:
        check_attestation(
            args.provenance_verification, "https://slsa.dev/provenance/v1", predicate
        )
    args.output.write_text(json.dumps(predicate, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
