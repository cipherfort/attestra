# SPDX-License-Identifier: Apache-2.0
"""Alembic environment. Migrations are plain SQL (the verified DDL in schemas/database) executed as the migrator."""

from alembic import context
from sqlalchemy import create_engine

from aap.db import database_url


def run_migrations_online() -> None:
    engine = create_engine(database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, version_table_schema="public")
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
