from __future__ import annotations

import os
import re
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from .contracts import seed_control_plane
from .models import Base, TemplateVersion
from .templates import TEMPLATES


BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


def database_url() -> str:
    if value := os.getenv("BEYVRA_EMAIL_DATABASE_URL", ""):
        return value
    return Path(os.environ["BEYVRA_EMAIL_DATABASE_URL_FILE"]).read_text(
        encoding="utf-8"
    ).strip()


engine = create_engine(database_url(), pool_pre_ping=True)
Sessions = sessionmaker(engine, expire_on_commit=False)


def seed_templates() -> None:
    with Sessions() as db:
        seed_control_plane(db)
        for category, names in TEMPLATES.items():
            for name in names:
                if not db.get(TemplateVersion, (name, 1, "en")):
                    db.add(
                        TemplateVersion(
                            template_id=name,
                            version=1,
                            locale="en",
                            category=category,
                            subject="Beyvra notification",
                            text_body="{{ action }}",
                            html_body=(
                                "<p>{{ action }}</p><p>Access sensitive actions only "
                                "through the authenticated Beyvra application.</p>"
                            ),
                            required_variables=["action"],
                            active=True,
                        )
                    )
        db.commit()


def migration_main() -> None:
    if os.getenv("BEYVRA_EMAIL_MIGRATION_AUTHORIZED", "false").lower() != "true":
        raise RuntimeError("beyvra_email_migration_not_authorized")
    backup_id = os.getenv("BEYVRA_EMAIL_PREDEPLOY_BACKUP_ID", "")
    if BACKUP_ID.fullmatch(backup_id) is None:
        raise RuntimeError("beyvra_email_predeploy_backup_id_required")

    Base.metadata.create_all(engine)
    seed_templates()
    present = set(inspect(engine).get_table_names())
    missing = set(Base.metadata.tables) - present
    if missing:
        raise RuntimeError("beyvra_email_schema_verification_failed")
    print("BEYVRA_EMAIL_ONE_SHOT_MIGRATION=PASS")


if __name__ == "__main__":
    migration_main()
