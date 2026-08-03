"""Regression tests for issue #276 — explicit ``DATABASE_URL`` enforcement.

The KubeTix API must refuse to start when ``DATABASE_URL`` is unset, rather
than silently falling back to a local SQLite file. These tests pin that
behaviour and the wording of the resulting error message so operators get
a clear, actionable hint instead of a generic ``KeyError`` or a hidden
SQLite database.

We test ``_default_database_url()`` directly with ``monkeypatch`` rather
than reloading ``kubetix_api.database`` so that the module-level
``get_session_factory()`` call (which happens on import) is not duplicated
or torn down — reloading mid-session leaves stale references in modules
that have already imported ``database`` and breaks unrelated tests.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def database_module():
    """Import the database module (with the conftest-set DATABASE_URL)."""

    return importlib.import_module("kubetix_api.database")


def test_default_database_url_raises_when_unset(monkeypatch, database_module):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        database_module._default_database_url()
    message = str(excinfo.value)
    assert "DATABASE_URL" in message
    # The error must point operators at PostgreSQL so the next step is obvious.
    assert "postgresql" in message.lower()


def test_default_database_url_raises_when_empty(monkeypatch, database_module):
    monkeypatch.setenv("DATABASE_URL", "")
    with pytest.raises(RuntimeError):
        database_module._default_database_url()


def test_default_database_url_raises_when_whitespace(monkeypatch, database_module):
    monkeypatch.setenv("DATABASE_URL", "   ")
    with pytest.raises(RuntimeError):
        database_module._default_database_url()


def test_default_database_url_returns_value_when_set(monkeypatch, database_module):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./explicit_value_test.db")
    assert (
        database_module._default_database_url() == "sqlite:///./explicit_value_test.db"
    )
