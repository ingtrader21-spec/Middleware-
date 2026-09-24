from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
ContractName = Literal["event", "command"]
SpecializedContractName = Literal["telnexa_sms_command", "postly_social_command"]
CONTRACT_PATHS: dict[ContractName, Path] = {
    "event": ROOT / "contracts" / "platform" / "event-envelope.v1.schema.json",
    "command": ROOT / "contracts" / "platform" / "command-envelope.v1.schema.json",
}
SPECIALIZED_CONTRACT_PATHS: dict[SpecializedContractName, Path] = {
    "telnexa_sms_command": ROOT / "contracts" / "telnexa-sms-command.v1.schema.json",
    "postly_social_command": ROOT
    / "contracts"
    / "postly-social-command.v1.schema.json",
}


class CanonicalContractError(ValueError):
    pass


@lru_cache(maxsize=len(CONTRACT_PATHS))
def contract_schema(name: ContractName) -> dict[str, Any]:
    try:
        schema = json.loads(CONTRACT_PATHS[name].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalContractError(
            f"canonical {name} contract cannot be loaded"
        ) from exc
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=len(CONTRACT_PATHS))
def contract_validator(name: ContractName) -> Draft202012Validator:
    return Draft202012Validator(
        contract_schema(name),
        format_checker=FormatChecker(),
    )


def validate_contract(name: ContractName, instance: dict[str, Any]) -> None:
    error = next(
        iter(
            sorted(
                contract_validator(name).iter_errors(instance),
                key=lambda item: tuple(str(part) for part in item.absolute_path),
            )
        ),
        None,
    )
    if error is None:
        return
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise CanonicalContractError(
        f"canonical {name} contract rejected {location}: {error.message}"
    )


@lru_cache(maxsize=len(SPECIALIZED_CONTRACT_PATHS))
def specialized_contract_validator(
    name: SpecializedContractName,
) -> Draft202012Validator:
    try:
        schema = json.loads(
            SPECIALIZED_CONTRACT_PATHS[name].read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalContractError(
            f"specialized {name} contract cannot be loaded"
        ) from exc
    Draft202012Validator.check_schema(schema)
    canonical = contract_schema("command")
    registry = Registry().with_resource(
        canonical["$id"],
        Resource.from_contents(canonical),
    )
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def validate_specialized_contract(
    name: SpecializedContractName,
    instance: dict[str, Any],
) -> None:
    error = next(
        iter(
            sorted(
                specialized_contract_validator(name).iter_errors(instance),
                key=lambda item: tuple(
                    str(part) for part in item.absolute_path
                ),
            )
        ),
        None,
    )
    if error is None:
        return
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise CanonicalContractError(
        f"specialized {name} contract rejected {location}: {error.message}"
    )
