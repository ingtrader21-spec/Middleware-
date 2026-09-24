"""Odoo campaign design wire contract; this module never executes providers."""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    model_validator,
    field_validator,
)

LIST_RANGES = {
    "MOY": (11000, 11999),
    "COD": (21000, 21999),
    "SCP": (31000, 31999),
    "MBL": (41000, 41999),
    "RLP": (51000, 51999),
    "FTP": (61000, 61999),
    "TRX": (71000, 71999),
    "CAL": (81000, 81999),
    "TEST": (91000, 91999),
    "STAGING": (91000, 91999),
}
DIRECTIONS = {"inbound": "IN", "outbound": "OUT", "blended": "BLENDED"}
SCOPES = {"test": "TEST", "staging": "STAGING", "production": "PROD"}
LIVE_FLAGS = {
    "lead_publication",
    "agent_sync",
    "live_call_control",
    "production_dialing",
}
REQUIRED_INPUTS = {
    "default_language",
    "recording_policy",
    "default_lead_source_policy",
    "agent_roles",
    "transfer_roles",
    "callback_policy",
    "appointment_policy",
    "disposition_family",
    "script_template",
    "n8n_automation_template",
    "reporting_category",
    "activation_policy",
}


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def manifest_hash(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(
                part in str(k).lower()
                for part in (
                    "password",
                    "passwd",
                    "token",
                    "secret",
                    "credential",
                    "private_key",
                )
            )
            or contains_secret(v)
            for k, v in value.items()
        )
    return isinstance(value, list) and any(contains_secret(v) for v in value)


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DesignValidation(WireModel):
    status: Literal["READY", "BLOCKED"] = "READY"
    errors: list[str] = Field(default_factory=list, max_length=100)


class CampaignDesignConfiguration(WireModel):
    time_zone: str = Field(min_length=1, max_length=64)
    calling_hour_start: float = Field(ge=0, lt=24, allow_inf_nan=False, strict=True)
    calling_hour_end: float = Field(gt=0, le=24, allow_inf_nan=False, strict=True)
    consent_required: StrictBool
    dnc_enforced: StrictBool
    team_ids: list[StrictInt] = Field(max_length=1000)
    supervisor_ids: list[StrictInt] = Field(max_length=1000)
    campaign_type: str | None = None
    lead_source_id: StrictInt | None = None
    dialer_mode: str | None = None
    routing_strategy: str | None = None
    max_call_attempts: StrictInt = Field(default=1, ge=0, le=1000)
    max_retries: StrictInt = Field(default=0, ge=0, le=1000)
    callback_rule: str | bool | None = None
    escalation_rule: str | bool | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)

    @field_validator("time_zone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("unknown time zone") from exc
        return value

    @field_validator("team_ids", "supervisor_ids")
    @classmethod
    def identifiers(cls, values: list[int]) -> list[int]:
        if any(v <= 0 for v in values) or len(values) != len(set(values)):
            raise ValueError("identifiers must be positive and unique")
        return sorted(values)

    @model_validator(mode="after")
    def check_configuration(self):
        if self.calling_hour_end <= self.calling_hour_start:
            raise ValueError("calling-hour end must follow start")
        canonical(self.inputs)  # Reject non-finite or non-JSON policy values.
        if contains_secret(self.inputs):
            raise ValueError("secret-shaped input is prohibited")
        return self


class CampaignDesignInput(WireModel):
    schema_version: Literal["campaign-provisioning.v1"] = "campaign-provisioning.v1"
    event_id: str = Field(min_length=8, max_length=128)
    integration_uuid: str
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    design_request_revision: StrictInt = Field(default=1, ge=1)
    odoo_campaign_id: StrictInt = Field(gt=0)
    environment: Literal["test", "staging", "production"]
    business_unit: str
    purpose: str = Field(pattern=r"^[A-Z0-9]{2,16}$")
    direction: Literal["inbound", "outbound", "blended"]
    campaign_code: str
    expected_campaign_code: str
    owner_user_id: StrictInt = Field(gt=0)
    supervisor_user_id: StrictInt | None
    correlation_id: str = Field(min_length=8, max_length=128)
    validation: DesignValidation
    design_configuration: CampaignDesignConfiguration
    feature_flags: dict[str, StrictBool]

    @field_validator("integration_uuid")
    @classmethod
    def canonical_uuid(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("integration UUID must be canonical")
        return value

    @model_validator(mode="after")
    def check_identity(self):
        if self.business_unit not in LIST_RANGES:
            raise ValueError("unknown business unit")
        expected = f"{self.business_unit}-{self.purpose}-{DIRECTIONS[self.direction]}"
        if self.campaign_code != expected or self.expected_campaign_code != expected:
            raise ValueError("campaign code does not match its business scope")
        if self.supervisor_user_id is not None and self.supervisor_user_id <= 0:
            raise ValueError("supervisor identifier must be positive")
        if not LIVE_FLAGS.issubset(self.feature_flags) or any(
            self.feature_flags.values()
        ):
            raise ValueError("design requests must keep live flags false")
        if contains_secret(self.model_dump(mode="json")):
            raise ValueError("secret-shaped input is prohibited")
        return self

    def payload_hash(self) -> str:
        return manifest_hash(
            self.model_dump(mode="json", exclude={"event_id", "correlation_id"})
        )

    def validation_errors(self) -> list[str]:
        errors = list(self.validation.errors)
        if self.validation.status == "BLOCKED" and not errors:
            errors.append("ODOO_VALIDATION_BLOCKED")
        if self.supervisor_user_id not in self.design_configuration.supervisor_ids:
            errors.append("SUPERVISOR_REQUIRED")
        for key in sorted(REQUIRED_INPUTS):
            if self.design_configuration.inputs.get(key) in (None, "", [], {}):
                errors.append(f"DESIGN_INPUT_REQUIRED:{key}")
        roles = self.design_configuration.inputs.get("agent_roles")
        if (
            not isinstance(roles, list)
            or not roles
            or any(
                not isinstance(role, str)
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", role) is None
                for role in roles
            )
        ):
            errors.append("AGENT_ROLES_INVALID")
        return list(dict.fromkeys(errors))


class CampaignApprovalInput(WireModel):
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    integration_uuid: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    business_unit: str = Field(
        pattern=r"^(MOY|COD|SCP|MBL|RLP|FTP|TRX|CAL|TEST|STAGING)$"
    )
    environment: Literal["test", "staging", "production"]
    design_revision: StrictInt = Field(ge=1)
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=8, max_length=512)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_reason(cls, value):
        return value.strip() if isinstance(value, str) else value


def build_manifest(
    request: CampaignDesignInput, revision: int, list_id: int
) -> dict[str, Any]:
    config = request.design_configuration
    inputs = config.inputs
    prefix = f"{request.business_unit}_{request.purpose}"
    roles = inputs.get("agent_roles")
    roles = roles if isinstance(roles, list) else []
    role_codes = sorted(
        {
            str(role).upper()
            for role in roles
            if isinstance(role, str)
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", role)
        }
    ) or ["AGENT"]
    return {
        "schema_version": "campaign-provisioning.v1",
        "environment": request.environment,
        "tenant_id": request.tenant_id,
        "integration_uuid": request.integration_uuid,
        "design_revision": revision,
        "business_unit": request.business_unit,
        "odoo": {
            "campaign_id": request.odoo_campaign_id,
            "campaign_code": request.campaign_code,
            "crm_team_code": f"{prefix}_TEAM",
            "owner_user_id": request.owner_user_id,
            "supervisor_user_id": request.supervisor_user_id,
            "design_configuration": config.model_dump(mode="json"),
        },
        "policies": {
            "time_zone": config.time_zone,
            "calling_hours": {
                "start": config.calling_hour_start,
                "end": config.calling_hour_end,
            },
            "consent_policy": {"required": config.consent_required},
            "dnc_policy": {"enforced": config.dnc_enforced},
            "recording_policy": inputs.get("recording_policy"),
            "transfer_policy": inputs.get("transfer_roles"),
            "callback_policy": inputs.get("callback_policy"),
            "appointment_policy": inputs.get("appointment_policy"),
            "activation_policy": inputs.get("activation_policy"),
        },
        "vicidial": {
            "campaign_id": request.campaign_code,
            "active": False,
            "default_list_id": list_id,
            "lists": [
                {"list_id": list_id, "code": f"{prefix}_PRIMARY_001", "active": False}
            ],
            "user_groups": [f"{prefix}_{role}" for role in role_codes],
            "inbound_groups": [f"{prefix}_INBOUND", f"{prefix}_CLOSERS"],
            "scripts": [f"{prefix}_{role}_V{revision}" for role in role_codes],
            "disposition_set": f"{prefix}_DISPOSITIONS_V{revision}",
        },
        "n8n": {
            "scope": f"{SCOPES[request.environment]}-{request.business_unit}-{request.purpose}-V{revision}",
            "workflow_template": inputs.get("n8n_automation_template"),
            "workflows_active": False,
        },
        "reporting": {"category": inputs.get("reporting_category")},
        "approval": {"state": "preview", "provisioning_authorized": False},
        "lifecycle": {"state": "approval_pending"},
        "validation_errors": request.validation_errors(),
        "feature_flags": {
            key: False
            for key in sorted(
                LIVE_FLAGS
                | {
                    "vicidial_writes",
                    "n8n_production",
                    "email",
                    "sms",
                    "ai_actions",
                }
            )
        },
    }
