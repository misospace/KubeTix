"""Pytest config: make the kubetix_api package importable.

This conftest also installs a small autouse fixture that resets the cached
SQLAlchemy engine between tests. The previous approach forced test files to
mutate ``os.environ`` before the package was imported and then evict
``kubetix_api.database`` from ``sys.modules`` to force a re-import. That was
fragile and order-dependent; resetting the engine lazily instead is safe.
"""

import os
import sys

# Ensure DATABASE_URL is set *before* any kubetix_api modules are imported
# during test collection. Individual tests can override via monkeypatch.
os.environ.setdefault("DATABASE_URL", "sqlite:///test_default.sqlite")
os.environ.setdefault("KUBETIX_SECRET_KEY", "test-secret-key-for-pytest-suite")

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(autouse=True)
def _reset_db_engine(tmp_path, monkeypatch):
    """Drop the cached engine so each test gets a fresh one based on current env."""
    # Set a per-test database URL before importing.
    db_file = tmp_path / "test.sqlite"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")

    # Import lazily so monkeypatch.setenv() in individual tests wins.
    from kubetix_api import database

    database.reset_engine()
    database.init_db()
    try:
        yield
    finally:
        database.reset_engine()
