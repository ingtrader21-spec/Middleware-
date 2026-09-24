"""SQLAlchemy engine/session management with transaction-local tenant context."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .config import RuntimeSettings


@dataclass(slots=True)
class Database:
    engine: Engine
    sessions: sessionmaker[Session]

    @classmethod
    def create(cls, settings: RuntimeSettings) -> "Database":
        engine = create_engine(
            settings.database_url.get_secret_value(),
            future=True,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_recycle=300,
            connect_args={
                "connect_timeout": 5,
                "application_name": settings.service_name,
            },
        )
        return cls(
            engine=engine,
            sessions=sessionmaker(
                bind=engine,
                autoflush=False,
                expire_on_commit=False,
                future=True,
            ),
        )

    @contextmanager
    def session(self, tenant_id: UUID | None = None) -> Generator[Session, None, None]:
        session = self.sessions()
        try:
            with session.begin():
                if tenant_id is not None:
                    session.execute(
                        text("SELECT set_config('codestra.tenant_id', :tenant_id, true)"),
                        {"tenant_id": str(tenant_id)},
                    )
                yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def ping(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def migration_head(self) -> str | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).scalar_one_or_none()
        return str(row) if row is not None else None

    def dispose(self) -> None:
        self.engine.dispose()
