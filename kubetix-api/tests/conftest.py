"""Pytest config: make the kubetix_api package importable.

This conftest also installs a small autouse fixture that resets the cached
SQLAlchemy engine between tests. The previous approach forced test files to
mutate ``os.environ`` before the package was imported and then evict
``kubetix_api.database`` from ``sys.modules`` to force a re-import. That was
fragile and order-dependent; resetting the engine lazily instead is safe.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(autouse=True)
def _reset_db_engine():
    """Drop the cached engine so each test gets a fresh one based on current env."""
    # Import lazily so monkeypatch.setenv() in individual tests wins.
    from kubetix_api import database

    database.reset_engine()
    try:
        yield
    finally:
        database.reset_engine()
