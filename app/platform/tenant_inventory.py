from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
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

INVENTORY_RELATIVE_PATH = Path("config/tenant-table-inventory.v1.json")
INVENTORY_SCHEMA_VERSION = "1.0"


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


def validate_inventory(
    repo_root: str | Path,
    *,
    require_snapshot: bool = True,
) -> tuple[TenantTableRecord, ...]:
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

    if require_snapshot:
        validate_snapshot_matches_migrations(repo_root, records)
    return records


def inventory_document(records: Iterable[TenantTableRecord]) -> dict[str, object]:
    rows = [asdict(record) for record in sorted(records, key=lambda item: item.table)]
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "authority": "migration-derived-reviewed-snapshot",
        "generated_from": "migrations/**/*.sql + migrations/**/*.py",
        "tables": rows,
    }


def write_inventory_snapshot(
    repo_root: str | Path,
    *,
    destination: str | Path | None = None,
) -> Path:
    root = Path(repo_root)
    records = validate_inventory(root, require_snapshot=False)
    path = Path(destination) if destination else root / INVENTORY_RELATIVE_PATH
    if not path.is_absolute():
        path = root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = inventory_document(records)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_inventory_snapshot(
    repo_root: str | Path,
) -> tuple[TenantTableRecord, ...]:
    root = Path(repo_root)
    path = root / INVENTORY_RELATIVE_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load reviewed tenant inventory snapshot: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("tenant inventory snapshot root must be an object")
    if payload.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise ValueError("tenant inventory snapshot schema_version mismatch")
    if payload.get("authority") != "migration-derived-reviewed-snapshot":
        raise ValueError("tenant inventory snapshot authority mismatch")
    rows = payload.get("tables")
    if not isinstance(rows, list):
        raise ValueError("tenant inventory snapshot tables must be an array")

    records: list[TenantTableRecord] = []
    seen: set[str] = set()
    expected_keys = {
        "table",
        "family",
        "ownership",
        "tenant_representation",
        "source",
        "remediation",
        "parent_table",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != expected_keys:
            raise ValueError(
                f"tenant inventory snapshot tables[{index}] shape is invalid"
            )
        table = row.get("table")
        if not isinstance(table, str) or not table:
            raise ValueError(
                f"tenant inventory snapshot tables[{index}] table is invalid"
            )
        if table in seen:
            raise ValueError(f"duplicate table in tenant inventory snapshot: {table}")
        seen.add(table)
        records.append(TenantTableRecord(**row))

    return tuple(sorted(records, key=lambda item: item.table))


def validate_snapshot_matches_migrations(
    repo_root: str | Path,
    records: Iterable[TenantTableRecord] | None = None,
) -> tuple[TenantTableRecord, ...]:
    root = Path(repo_root)
    actual = tuple(records) if records is not None else scan_tenant_inventory(root)
    reviewed = load_inventory_snapshot(root)
    if actual == reviewed:
        return actual

    actual_by_table = {record.table: record for record in actual}
    reviewed_by_table = {record.table: record for record in reviewed}
    added = sorted(actual_by_table.keys() - reviewed_by_table.keys())
    removed = sorted(reviewed_by_table.keys() - actual_by_table.keys())
    changed = sorted(
        table
        for table in actual_by_table.keys() & reviewed_by_table.keys()
        if actual_by_table[table] != reviewed_by_table[table]
    )
    details: list[str] = []
    if added:
        details.append("new tables=" + ",".join(added))
    if removed:
        details.append("removed tables=" + ",".join(removed))
    if changed:
        details.append("reclassified tables=" + ",".join(changed))
    raise ValueError(
        "tenant inventory drift; regenerate and review "
        f"{INVENTORY_RELATIVE_PATH.as_posix()}: " + "; ".join(details)
    )


def inventory_by_table(
    repo_root: str | Path,
) -> dict[str, TenantTableRecord]:
    return {
        record.table: record
        for record in validate_inventory(repo_root, require_snapshot=True)
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate or regenerate the reviewed Middleware tenant-table inventory."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the reviewed snapshot from current migration sources.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.write:
            path = write_inventory_snapshot(args.repo_root)
            records = load_inventory_snapshot(args.repo_root)
            print(
                json.dumps(
                    {
                        "status": "WROTE",
                        "path": str(path),
                        "tables": len(records),
                        "remediations": len(remediation_list(records)),
                    },
                    sort_keys=True,
                )
            )
            return 0
        records = validate_inventory(args.repo_root, require_snapshot=True)
    except ValueError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 2

    counts: dict[str, int] = {}
    for record in records:
        counts[record.ownership] = counts.get(record.ownership, 0) + 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "tables": len(records),
                "ownership_counts": counts,
                "remediations": len(remediation_list(records)),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
