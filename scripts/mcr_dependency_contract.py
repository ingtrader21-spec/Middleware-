"""Closed parser for the immutable MCR A-L cross-repository handoff contract."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/mcr-m-dependencies.v1.json"
DEPENDENCIES = tuple("ABCDEFHIJKL")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def load_dependency_contract(path: Path = CONTRACT_PATH) -> dict[str, dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not (
        isinstance(document, dict)
        and set(document) == {"schema_version", "dependencies"}
        and document.get("schema_version") == 1
        and isinstance(document.get("dependencies"), dict)
    ):
        raise ValueError("invalid MCR dependency contract")
    dependencies = document["dependencies"]
    if set(dependencies) != set(DEPENDENCIES):
        raise ValueError("incomplete dependency handoffs")
    for lane, record in dependencies.items():
        if not (
            isinstance(record, dict)
            and set(record) == {"repository", "sha"}
            and isinstance(record["repository"], str)
            and record["repository"].startswith("ingtrader21-spec/")
            and isinstance(record["sha"], str)
            and SHA.fullmatch(record["sha"])
        ):
            raise ValueError(f"{lane}: invalid dependency record")
    return dependencies
