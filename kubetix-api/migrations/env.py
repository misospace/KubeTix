"""Alembic environment.

Reads ``DATABASE_URL`` from the environment so the same migrations can target
SQLite (tests), PostgreSQL (production Bitnami sub-chart), or any other engine
SQLAlchemy supports. ``render_as_batch=True`` is enabled because SQLite cannot
``ALTER TABLE`` directly; the batching rewrite produces per-engine statements
under the hood.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the kubetix_api package importable when ``alembic`` is invoked from
# the ``kubetix-api/`` directory (the default ``script_location`` layout).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Importing the package brings every model class into scope, populating
# ``Base.metadata`` with the full set of tables.
from kubetix_api.models import Base  # noqa: E402

config = context.config

# ``alembic.ini`` leaves ``sqlalchemy.url`` blank. Inject the URL from the
# environment so secrets aren't baked into the repository.
database_url = os.environ.get("DATABASE_URL")
if database_url:
    # Alembic expects SQLAlchemy URL strings; ``sqlite:///<path>`` works
    # directly. Strip the SQLAlchemy ``+driver`` markers (e.g. ``+psycopg``)
    # for the Alembic engine.
    config.set_main_option("sqlalchemy.url", database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (against a live DBAPI connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
