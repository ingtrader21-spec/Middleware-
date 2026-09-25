"""Local-only frozen contract resolution for runtime validation and OpenAPI."""

from functools import lru_cache
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

DIRECTORY = Path(__file__).resolve().parents[2] / "contracts/campaign-recycling"


@lru_cache(maxsize=16)
def document(name: str):
    path = DIRECTORY / name
    if path.parent != DIRECTORY:
        raise ValueError("contract must be local")
    return (
        yaml.safe_load(path.read_text())
        if name.endswith(".yaml")
        else json.loads(path.read_text())
    )


def resolve(value: Any, name: str):
    if isinstance(value, list):
        return [resolve(item, name) for item in value]
    if not isinstance(value, dict):
        return value
    if "$ref" in value:
        filename, _, pointer = value["$ref"].partition("#")
        filename = filename.removeprefix("./") or name
        target = document(filename)
        for part in pointer.strip("/").split("/") if pointer else []:
            target = target[part.replace("~1", "/").replace("~0", "~")]
        return resolve(target, filename)
    return {
        key: resolve(item, name)
        for key, item in value.items()
        if key not in {"$id", "$schema", "$defs"} and not key.startswith("x-")
    }


@lru_cache(maxsize=8)
def schema(name: str):
    return resolve(document(name), name)


@lru_cache(maxsize=8)
def validator(name: str):
    return Draft202012Validator(
        schema(name), format_checker=Draft202012Validator.FORMAT_CHECKER
    )


def journey_response(page, tenant_id: str, lead_id: str):
    identity = {"schema_version": "1.0", "tenant_id": tenant_id, "lead_id": lead_id}
    transitions = []
    for row in page["lifecycle"]:
        event = {
            key: value
            for key, value in row.items()
            if key not in {"event_id", "version"}
        }
        transitions.append({**identity, **event, "lifecycle_version": row["version"]})
    return {
        "schema_version": "1.0",
        "lead_id": lead_id,
        "lifecycle_state": page["current"]["state"],
        "lifecycle_version": page["current"]["version"],
        "transitions": transitions,
        "channel_health": page["channel_health"],
        "suppressions": page["suppressions"],
        "exposures": [{**identity, **row} for row in page["exposures"]],
        "next_cursor": page["next_cursor"],
    }
