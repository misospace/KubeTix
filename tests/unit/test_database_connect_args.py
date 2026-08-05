"""Regression tests for issue #310 — dialect-safe ``connect_args``.

The original ``database.get_engine()`` always passed
``{"check_same_thread": False}`` to ``sqlalchemy.create_engine``. That
keyword is only valid for the ``sqlite3`` driver; passing it to
``postgresql://`` / ``postgresql+psycopg2://`` raises
``TypeError: 'check_same_thread' is an invalid keyword argument for this
function`` *before* a missing ``psycopg2`` driver is even reached.

These tests pin the behaviour: ``check_same_thread`` is attached for
``sqlite`` URLs only, and every other dialect receives an empty
``connect_args`` so SQLAlchemy can pick a sensible default.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_engine_cache():
    """Force ``database.get_engine()`` to rebuild between tests."""
    from kubetix_api import database

    database._engine = None
    yield
    database._engine = None


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///./local.db",
        "sqlite:////tmp/test.db",
    ],
)
def test_connect_args_sqlite_uses_check_same_thread(monkeypatch, url):
    monkeypatch.setenv("DATABASE_URL", url)
    from kubetix_api import database

    args = database._build_connect_args(url)
    assert args == {"check_same_thread": False}

    # ``create_engine`` accepts the kwargs without raising — for sqlite
    # this is the same path as the original behaviour.
    engine = database.get_engine()
    assert engine.url.drivername == "sqlite"


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://kubetix:kubetix@kubetix-postgresql:5432/kubetix",
        "postgresql+psycopg2://kubetix:kubetix@kubetix-postgresql:5432/kubetix",
        "postgresql+psycopg://kubetix:kubetix@kubetix-postgresql:5432/kubetix",
        "mysql+pymysql://kubetix:kubetix@kubetix-mysql:3306/kubetix",
    ],
)
def test_connect_args_non_sqlite_omits_check_same_thread(monkeypatch, url):
    """Issue #310: ``check_same_thread`` must not leak to non-sqlite drivers."""
    monkeypatch.setenv("DATABASE_URL", url)
    from kubetix_api import database

    args = database._build_connect_args(url)
    assert "check_same_thread" not in args

    # ``create_engine`` accepts the (empty) ``connect_args`` without
    # raising. Driver import may still fail if ``psycopg2`` / ``psycopg``
    # isn't installed in this Python — that is exactly the failure path
    # this issue is fixing at the chart / image layer, not something
    # this module can paper over. Skip when the driver is missing.
    try:
        engine = database.get_engine()
    except ModuleNotFoundError as exc:  # pragma: no cover — depends on env
        pytest.skip(f"DBAPI driver not installed in test env: {exc}")
    assert engine.url.drivername.split("+")[0] in {"postgresql", "mysql"}
