#!/usr/bin/env python3
"""Check the generated preview against the actual Odoo source validator.

This is a source contract test, not a deployed Odoo/n8n acceptance test.
"""

import argparse
import ast
import hashlib
import json
import re
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.campaign_design_contract import (  # noqa: E402
    CampaignDesignInput,
    LIST_RANGES,
    build_manifest,
    canonical,
    contains_secret,
    manifest_hash,
)


def require(condition: bool, message: str) -> None:
    """Keep contract checks active even when the interpreter uses -O."""
    if not condition:
        raise RuntimeError(message)


def verify(odoo_root: Path) -> dict:
    addon = odoo_root / "custom-addons/call_center_campaign"
    source = addon / "models/automatic_provisioning_revision.py"
    tree = ast.parse(source.read_text())
    wanted = {"_validate_manifest", "_record_preview"}
    methods = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    if {m.name for m in methods} != wanted:
        raise ValueError("Odoo design validation methods are missing")
    namespace = {
        "ValidationError": ValueError,
        "hashlib": hashlib,
        "re": re,
        "DESIGN_MANIFEST_SCHEMA": "campaign-provisioning.v1",
        "LIST_ID_RANGES": LIST_RANGES,
        "REQUIRED_MANIFEST_POLICY_KEYS": {
            "calling_hours",
            "time_zone",
            "consent_policy",
            "dnc_policy",
            "recording_policy",
            "transfer_policy",
        },
        "ENVIRONMENT_SCOPE_CODES": {
            "test": "TEST",
            "staging": "STAGING",
            "production": "PROD",
        },
        "contains_secret_key": contains_secret,
        "normalized_hash": lambda value: str(value or "")
        .removeprefix("sha256:")
        .lower(),
        "canonical_json": canonical,
        "fields": SimpleNamespace(
            Datetime=SimpleNamespace(now=lambda: datetime.now(timezone.utc))
        ),
    }
    module = ast.Module(body=list(methods), type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    request = CampaignDesignInput.model_validate(
        json.loads(
            (ROOT / "contracts/campaign-design-request.v1.fixture.json").read_text()
        )
    )
    manifest = build_manifest(request, request.design_request_revision, 91000)

    class Revision(SimpleNamespace):
        def ensure_one(self):
            return None

        def _system_write(self, values):
            self.saved = values
            return values

    setattr(Revision, "_validate_manifest", namespace["_validate_manifest"])
    setattr(Revision, "_record_preview", namespace["_record_preview"])
    revision = Revision()
    revision.campaign_id = SimpleNamespace(
        _business_unit_code=lambda: request.business_unit,
        id=request.odoo_campaign_id,
        code=request.campaign_code,
        purpose_code=request.purpose,
        create_uid=SimpleNamespace(id=request.owner_user_id),
        supervisor_ids=SimpleNamespace(ids=[request.supervisor_user_id]),
        timezone=request.design_configuration.time_zone,
        design_request_revision=request.design_request_revision,
        _design_validation_errors=lambda: [],
    )
    revision.environment = request.environment
    revision.integration_uuid = request.integration_uuid
    revision.revision = request.design_request_revision
    revision.state = "requested"
    revision.validation_errors_json = []
    result = {
        "manifest": manifest,
        "manifest_hash": manifest_hash(manifest),
        "design_revision": request.design_request_revision,
        "validation_errors": [],
    }
    revision._record_preview(result)
    require(revision.saved["state"] == "ready", "Odoo preview did not become ready")
    require(
        revision.saved["manifest_json"] == manifest,
        "Odoo changed the canonical campaign manifest",
    )
    tampered = json.loads(json.dumps(result))
    tampered["manifest"]["n8n"]["workflows_active"] = True
    tampered["manifest_hash"] = manifest_hash(tampered["manifest"])
    try:
        revision._record_preview(tampered)
    except ValueError:
        pass
    else:
        raise AssertionError("Odoo accepted an active n8n preview")
    transport_source = addon / "models/outbox.py"
    transport_tree = ast.parse(transport_source.read_text())
    tenant_method = next(
        node
        for cls in transport_tree.body
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "_campaign_tenant_id"
    )
    environment = {
        "CODESTRA_MIDDLEWARE_CAMPAIGN_TENANTS": canonical(
            {request.business_unit: request.tenant_id}
        )
    }
    transport_namespace = {
        "json": json,
        "os": SimpleNamespace(environ=environment),
        "ValidationError": ValueError,
    }
    exec(
        compile(
            ast.fix_missing_locations(
                ast.Module(body=[tenant_method], type_ignores=[])
            ),
            str(transport_source),
            "exec",
        ),
        transport_namespace,
    )
    event = SimpleNamespace(
        ensure_one=lambda: None, business_unit_code=request.business_unit
    )
    resolve_tenant = cast(
        Callable[[Any], str], transport_namespace["_campaign_tenant_id"]
    )
    require(callable(resolve_tenant), "Odoo tenant resolver is not callable")
    require(
        resolve_tenant(event) == request.tenant_id,
        "Odoo resolved a different campaign tenant",
    )
    environment.clear()
    try:
        resolve_tenant(event)
    except ValueError:
        pass
    else:
        raise AssertionError("Odoo accepted a missing tenant binding")
    return {
        "source_contract": "PASS",
        "tenant_binding_verified": True,
        "odoo_transport_sha256": hashlib.sha256(
            transport_source.read_bytes()
        ).hexdigest(),
        "odoo_validator_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "manifest_sha256": result["manifest_hash"],
        "preview_state": "ready",
        "active_workflow_rejected": True,
        "production_execution": "NOT_RUN",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--odoo-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.odoo_source), sort_keys=True))
