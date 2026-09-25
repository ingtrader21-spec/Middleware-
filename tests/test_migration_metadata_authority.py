from __future__ import annotations

from app.db import recording_models as _recording_models  # noqa: F401
from app.db.models import Base
from app.email.models import Base as EmailBase
from app.monitoring.store import metadata as monitoring_metadata


def test_migration_metadata_covers_all_declared_model_families() -> None:
    db_tables = set(Base.metadata.tables)
    email_tables = set(EmailBase.metadata.tables)
    monitoring_tables = set(monitoring_metadata.tables)

    assert {
        "recordings",
        "recording_upload_reservations",
        "recording_objects",
    } <= db_tables
    assert {
        "email_notification",
        "email_outbox",
        "email_delivery_event",
    } <= email_tables
    assert monitoring_tables

    combined = db_tables | email_tables | monitoring_tables
    assert len(combined) == len(db_tables) + len(email_tables) + len(monitoring_tables)