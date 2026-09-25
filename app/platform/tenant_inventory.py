from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_CREATE_TABLE_RE = re.compile(
    r"CREATE TABLE(?: IF NOT EXISTS)?\s+([A-Za-z0-9_.]+)\s*\((.*?)\)"
    r"(?=\s*(?:;|\)\s*\"\"\"|op\.|$))",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class TenantTableRecord:
    table: str
    family: str
    ownership: str
    tenant_representation: str
    source: str
    remediation: str | None = None
    parent_table: str | None = None


# These are intentionally limited to relationships verified in the current
# migration source. New inherited-tenancy entries require an explicit source
# relationship and test rather than a naming guess.
_INHERITED_TENANT = {
    "agent_provisioning_step": "agent_provisioning_request",
    "agent_provisioning_audit": "agent_provisioning_request",
    "callback_delivery": "callback_record",
    "callback_popup_ack": "callback_record",
}

_GLOBAL_TABLES = {
    "middleware_schema_migrations",
    "middleware_automation_schema_migrations",
}


def _family(table: str) -> str:
    rules = (
        ("middleware_automation_", "automation"),
        ("middleware_communication_", "communications"),
        ("middleware_observability_", "monitoring"),
        ("middleware_command", "command"),
        ("middleware_control_", "control"),
        ("middleware_operation_", "operation"),
        ("middleware_outbox", "outbox"),
        ("middleware_inbox", "inbox"),
        ("middleware_event_", "event"),
        ("middleware_reconciliation_", "reconciliation"),
        ("middleware_realtime_", "telephony"),
        ("agent_call_", "telephony"),
        ("callback_", "telephony"),
        ("agent_provisioning_", "provisioning"),
        ("platform_", "service_catalog"),
        ("lead_automation_", "automation"),
        ("social_", "social"),
        ("website_", "website"),
        ("managed_webhook_", "website"),
        ("ai_", "ai"),
        ("tts_", "ai"),
        ("recording", "recordings"),
        ("telnexa_", "communications"),
        ("klyrow_", "communications"),
        ("breero_", "breero"),
        ("integration_", "legacy"),
        ("event_model_", "legacy"),
        ("idempotency_", "legacy"),
    )
    for prefix, family in rules:
        if table.startswith(prefix):
            return family
    return "legacy"


def _iter_migration_files(root: Path) -> Iterable[Path]:
    yield from sorted((root / "migrations").rglob("*.sql"))
    yield from sorted((root / "migrations").rglob("*.py"))


def scan_tenant_inventory(repo_root: str | Path) -> tuple[TenantTableRecord, ...]:
    root = Path(repo_root)
    seen: dict[str, TenantTableRecord] = {}
    for path in _iter_migration_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in _CREATE_TABLE_RE.finditer(text):
            table = match.group(1).strip('"')
            body = match.group(2)
            source = str(path.relative_to(root)).replace("\\", "/")
            has_tenant = bool(
                re.search(r"\btenant_id\b", body, flags=re.IGNORECASE)
            )
            tenant_not_null = bool(
                re.search(
                    r"\btenant_id\b[^,\n]*\bNOT\s+NULL\b",
                    body,
                    flags=re.IGNORECASE,
                )
            )

            if has_tenant:
                ownership = "tenant_owned"
                tenant_representation = (
                    "tenant_id_not_null" if tenant_not_null else "tenant_id_nullable"
                )
                remediation = (
                    None
                    if tenant_not_null
                    else "make tenant_id NOT NULL after compatibility validation"
                )
                parent_table = None
            elif table in _GLOBAL_TABLES:
                ownership = "global"
                tenant_representation = "not_applicable"
                remediation = None
                parent_table = None
            elif table in _INHERITED_TENANT:
                ownership = "tenant_owned_inherited"
                tenant_representation = "parent_join"
                parent_table = _INHERITED_TENANT[table]
                remediation = (
                    "add explicit tenant_id and tenant-matching parent constraint"
                )
            else:
                ownership = "review_required"
                tenant_representation = "none_explicit"
                remediation = (
                    "classify tenant ownership before adding RLS or tenant columns"
                )
                parent_table = None

            record = TenantTableRecord(
                table=table,
                family=_family(table),
                ownership=ownership,
                tenant_representation=tenant_representation,
                source=source,
                remediation=remediation,
                parent_table=parent_table,
            )
            prior = seen.get(table)
            if prior and prior != record:
                raise ValueError(
                    f"table {table} has conflicting inventory definitions: "
                    f"{prior.source} vs {source}"
                )
            seen[table] = record

    return tuple(sorted(seen.values(), key=lambda item: item.table))


def remediation_list(
    records: Iterable[TenantTableRecord],
) -> tuple[TenantTableRecord, ...]:
    return tuple(record for record in records if record.remediation)


def validate_inventory(repo_root: str | Path) -> tuple[TenantTableRecord, ...]:
    records = scan_tenant_inventory(repo_root)
    if not records:
        raise ValueError("tenant inventory is empty")

    tables = {record.table for record in records}
    required_core = {
        "middleware_commands",
        "middleware_command_attempts",
        "middleware_command_audit",
        "middleware_inbox",
        "middleware_outbox",
        "middleware_event_ledger",
        "middleware_reconciliation_audit",
    }
    missing = sorted(required_core - tables)
    if missing:
        raise ValueError(f"core durable tables missing from inventory: {missing}")

    for record in records:
        if (
            record.ownership == "tenant_owned"
            and record.tenant_representation != "tenant_id_not_null"
        ):
            raise ValueError(
                f"tenant-owned table is not fail-closed: {record.table}"
            )
        if record.ownership == "tenant_owned_inherited":
            if not record.parent_table or record.parent_table not in tables:
                raise ValueError(
                    f"inherited tenant parent missing for {record.table}"
                )

    return records
