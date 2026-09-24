#!/usr/bin/env python3
"""Normalize Trivy and Grype JSON without suppressing or lowering findings."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


FIELDS = (
    "vulnerability_id",
    "package",
    "installed_version",
    "package_path",
    "severity",
    "fixed_versions",
    "scanners",
)


def text(value: object) -> str:
    return "" if value is None else str(value)


def add(rows: dict[tuple[str, ...], dict[str, str]], *, scanner: str, vulnerability_id: object,
        package: object, installed: object, path: object, severity: object, fixes: list[object]) -> None:
    identity = (text(vulnerability_id), text(package), text(installed), text(path))
    if not all(identity[:3]):
        raise ValueError(f"incomplete {scanner} finding identity: {identity}")
    row = rows.setdefault(identity, {
        "vulnerability_id": identity[0], "package": identity[1],
        "installed_version": identity[2], "package_path": identity[3],
        "severity": text(severity).upper(), "fixed_versions": "", "scanners": "",
    })
    severities = {"UNKNOWN": 0, "NEGLIGIBLE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
    candidate = text(severity).upper()
    if severities.get(candidate, 0) > severities.get(row["severity"], 0):
        row["severity"] = candidate
    row["fixed_versions"] = ";".join(sorted(set(filter(None, row["fixed_versions"].split(";") + [text(v) for v in fixes]))))
    row["scanners"] = ";".join(sorted(set(filter(None, row["scanners"].split(";") + [scanner]))))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    rows: dict[tuple[str, ...], dict[str, str]] = {}
    trivy = json.loads(args.trivy.read_text(encoding="utf-8"))
    for result in trivy.get("Results") or []:
        target = result.get("Target", "")
        for finding in result.get("Vulnerabilities") or []:
            add(rows, scanner="Trivy", vulnerability_id=finding.get("VulnerabilityID"),
                package=finding.get("PkgName"), installed=finding.get("InstalledVersion"),
                path=finding.get("PkgPath") or target, severity=finding.get("Severity"),
                fixes=[finding.get("FixedVersion")])
    grype = json.loads(args.grype.read_text(encoding="utf-8"))
    for match in grype.get("matches") or []:
        vulnerability, artifact = match.get("vulnerability") or {}, match.get("artifact") or {}
        locations = artifact.get("locations") or [{}]
        for location in locations:
            add(rows, scanner="Grype", vulnerability_id=vulnerability.get("id"),
                package=artifact.get("name"), installed=artifact.get("version"),
                path=location.get("path", ""), severity=vulnerability.get("severity"),
                fixes=(vulnerability.get("fix") or {}).get("versions") or [])
    ordered = [rows[key] for key in sorted(rows)]
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(ordered)
    counts = Counter(row["severity"] for row in ordered)
    args.summary.write_text(json.dumps({
        "deduplicated_finding_count": len(ordered),
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "finding_suppression_count": 0,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
