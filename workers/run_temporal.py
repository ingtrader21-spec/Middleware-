#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio.worker import Worker

from app.core.config import ConfigurationError, Settings
from app.commands import PostgresCommandStore
from app.klyrow_alert_adapter import KlyrowAlertAdapter
from app.klyrow_email_adapter import KlyrowEmailAdapter
from app.odoo_provider_adapter import OdooProviderAdapter
from app.postly_social_adapter import PostlySocialAdapter
from app.telnexa_provider_adapter import TelnexaSmsAdapter
from app.vicidial_internal_call_adapter import VicidialInternalCallAdapter
from app.temporal_activities import (
    CommandLedgerWorkflowActivities,
    FailClosedWorkflowActivities,
)
from app.temporal_runtime import connect_temporal
from app.temporal_workflows import WORKFLOWS


def build_command_activities(
    settings: Settings,
    command_store: PostgresCommandStore,
) -> CommandLedgerWorkflowActivities:
    """Wire every reviewed provider adapter into the durable Temporal worker.

    Adapter construction does not authorize delivery. Each adapter re-checks
    its individual effect gate at execution time and resolves provider secrets
    only after that gate permits the operation.
    """

    return CommandLedgerWorkflowActivities(
        command_store,
        OdooProviderAdapter(settings),
        KlyrowAlertAdapter(settings),
        telnexa_sms=TelnexaSmsAdapter(settings),
        klyrow_email=KlyrowEmailAdapter(settings),
        postly_social=PostlySocialAdapter(settings),
        vicidial_internal=VicidialInternalCallAdapter(settings),
    )


async def main() -> None:
    settings = Settings.from_env()
    if settings.temporal_worker_mode == "disabled":
        raise ConfigurationError(
            "TEMPORAL_WORKER_MODE=disabled; workflow worker is intentionally disabled"
        )
    if settings.database_url is None:
        raise ConfigurationError("DATABASE_URL is required for the Temporal worker")
    client = await connect_temporal(settings)
    command_store = await PostgresCommandStore.connect(
        settings.database_url, environment=settings.app_env
    )
    try:
        safe_activities = FailClosedWorkflowActivities()
        command_activities = build_command_activities(settings, command_store)
        worker = Worker(
            client,
            task_queue=settings.temporal_task_queue,
            workflows=list(WORKFLOWS),
            activities=[
                *safe_activities.registered(),
                *command_activities.registered(),
            ],
            graceful_shutdown_timeout=timedelta(seconds=30),
        )
        await worker.run()
    finally:
        await command_store.close()


if __name__ == "__main__":
    asyncio.run(main())
