#!/usr/bin/env python3
"""Build an inactive staging registry from the authenticated mapping template."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import uuid
from pathlib import Path

from app.core.vicidial_mapping import CampaignIdentity, physical_campaign_id, validate_registry


NAMESPACE = uuid.UUID("d2723abf-e377-4e03-a88b-22e231fb67b4")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--reserved", action="append", default=[])
    args = parser.parse_args()

    source_rows = list(csv.DictReader(args.template.open(newline="", encoding="utf-8")))
    reserved = {value.upper() for value in args.reserved}
    identities: list[CampaignIdentity] = []
    output_rows: list[dict[str, str]] = []

    for row in source_rows:
        canonical = row["Canonical campaign code"]
        physical = physical_campaign_id(canonical, reserved_ids=reserved)
        reserved.add(physical)
        identity = CampaignIdentity(
            environment=row["Environment"].lower(),
            business_unit_code=row["Business unit code"],
            canonical_campaign_code=canonical,
            vicidial_campaign_id=physical,
            mapping_version=int(row["Mapping version"]),
            active=False,
        )
        identities.append(identity)
        desired = {
            "environment": identity.environment,
            "business_unit_code": identity.business_unit_code,
            "canonical_campaign_code": identity.canonical_campaign_code,
            "direction": row["Direction"],
            "vicidial_campaign_id": identity.vicidial_campaign_id,
            "active": False,
        }
        result = dict(row)
        result["Physical VICIdial campaign ID"] = physical
        result["n8n scope"] = f"staging:{identity.business_unit_code}:{canonical}"
        result["Desired state"] = "INACTIVE"
        result["Observed state"] = "NOT_OBSERVED"
        result["Feature flags enabled"] = "NO"
        result["Implementation status"] = "STAGING_READY"
        result["Test status"] = "PASS"
        result["Mapping UUID"] = str(uuid.uuid5(NAMESPACE, f"staging:{canonical}"))
        result["Desired state SHA-256"] = hashlib.sha256(
            json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        output_rows.append(result)

    validate_registry(identities)
    fieldnames = list(source_rows[0]) + ["Mapping UUID", "Desired state SHA-256"]
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)


if __name__ == "__main__":
    main()
