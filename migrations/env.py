from logging.config import fileConfig
from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from app.db.models import Base
from app.monitoring.store import metadata as monitoring_metadata

config = context.config
supplied_connection = config.attributes.get("connection")
if supplied_connection is None:
    from app.core.config import settings
    # Percent-encoded credentials must survive ConfigParser interpolation.
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
if config.config_file_name and config.get_section("loggers"):
    fileConfig(config.config_file_name)
target_metadata = [Base.metadata, monitoring_metadata]


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection):
    context.configure(connection=connection, target_metadata=target_metadata, version_table_schema="public")
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations():
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online():
    import asyncio

    if supplied_connection is not None:
        do_run_migrations(supplied_connection)
    else:
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
