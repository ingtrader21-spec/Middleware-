"""Middleware never stores or returns a secret value; references stay inside their environment."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.secret_reference import (
    PIN_PATH,
    SecretReference,
    SecretReferenceError,
    canonical_digest,
    parse_references,
    references_for_environments,
    schema,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = {
    "environment": "staging",
    "service_id": "middleware",
    "secret_ref": "codestra/staging/middleware/api/database",
    "secret_class": "database_credentials",
}


def test_vendored_schema_matches_pin_and_model_forbidden_keys():
    assert canonical_digest(schema()) == PIN_PATH.read_text(encoding="utf-8").strip()
    assert {"value", "password", "token", "private_key", "client_secret"} <= set(
        schema()["x-codestra-forbidden-keys"]
    )


@pytest.mark.parametrize(
    "key",
    [
        "value",
        "password",
        "token",
        "private_key",
        "client_secret",
        "secret",
        "root_token",
        "db_password",
    ],
)
def test_value_bearing_keys_are_rejected(key):
    with pytest.raises((ValidationError, SecretReferenceError)):
        SecretReference.model_validate({**BASE, key: "hunter2"})
    with pytest.raises((ValidationError, SecretReferenceError)):
        SecretReference.model_validate(
            {**BASE, "lease_metadata": {"ttl_seconds": 30, key: "hunter2"}}
        )


def test_secret_shaped_strings_are_rejected_anywhere():
    with pytest.raises((ValidationError, SecretReferenceError)):
        SecretReference.model_validate({**BASE, "secret_owner": "hvs." + "A" * 40})


def test_reference_stays_inside_its_environment_and_uri_is_derived():
    reference = SecretReference.model_validate(BASE)
    assert (
        reference.reference_uri == "openbao://codestra/staging/middleware/api/database"
    )
    assert reference.public()["provider"] == "openbao"
    with pytest.raises(ValidationError):
        SecretReference.model_validate({**BASE, "environment": "production"})
    with pytest.raises(ValidationError):
        SecretReference.model_validate(
            {**BASE, "reference_uri": "openbao://codestra/staging/middleware/api/other"}
        )
    for bad in (
        "codestra/staging/middleware/api/*",
        "codestra/staging/../production/x",
        "codestra/staging",
        "kv/staging/x",
    ):
        with pytest.raises(ValidationError):
            SecretReference.model_validate({**BASE, "secret_ref": bad})


def test_parse_references_rejects_duplicates_and_undeclared_environments():
    parsed = parse_references([BASE])
    assert parsed[0].environment == "staging"
    with pytest.raises(SecretReferenceError):
        parse_references([BASE, BASE])
    with pytest.raises(SecretReferenceError):
        references_for_environments(parsed, ["production"])
    with pytest.raises(SecretReferenceError):
        parse_references({"not": "a list"})


def test_validator_script_passes_offline():
    result = subprocess.run(
        [sys.executable, "-m", "scripts.validate_secret_reference_contract"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "SECRET_REFERENCE_CONTRACT=PASS" in result.stdout
    assert "SECRET_VALUES_STORED_BY_MIDDLEWARE=NEVER" in result.stdout
