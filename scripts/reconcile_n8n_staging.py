#!/usr/bin/env python3
"""Create a secret-free, deterministic n8n staging classification manifest."""

import argparse
import hashlib
import json
from pathlib import Path


ACTIVE_RUNTIME = {
    "CdstSocialEventRouterV1": "integrations/n8n/social-runtime/CdstSocialEventRouterV1.json",
    "CdstSocialAccountAuthRequiredV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialAccountDisconnectedV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialAnalyticsUpdatedV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialDeadLetterV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialLeadQualificationV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialNotificationV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialOdooProjectionV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialPostFailedV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
    "CdstSocialPostPublishedV1": "integrations/n8n/social-runtime/CdstSocialHandlersV1.json",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("export", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    rows = json.loads(args.export.read_text())
    manifest = []
    unclassified_active = []
    for row in sorted(rows, key=lambda item: (item.get("name", ""), item["id"])):
        source = ACTIVE_RUNTIME.get(row.get("name"))
        if row.get("active") and not source:
            unclassified_active.append(row["id"])
            classification = "unsafe_or_incomplete"
        elif source:
            classification = "required_and_active" if row.get("active") else "required_but_inactive"
        elif row.get("isArchived"):
            classification = "obsolete"
        else:
            classification = "staging_only"
        manifest.append({
            "workflow_id": row["id"],
            "version_id": row.get("activeVersionId") or row.get("versionId"),
            "name": row.get("name"),
            "classification": classification,
            "active": bool(row.get("active")),
            "source_file": source,
            "source_sha256": sha(args.repo / source) if source else None,
        })
    args.output.write_text(json.dumps({
        "schema": "codestra.n8n.staging-manifest.v1",
        "workflow_count": len(manifest),
        "unclassified_active_ids": unclassified_active,
        "workflows": manifest,
    }, indent=2) + "\n")
    if unclassified_active:
        raise SystemExit("active workflows require quarantine before certification")


if __name__ == "__main__":
    main()
