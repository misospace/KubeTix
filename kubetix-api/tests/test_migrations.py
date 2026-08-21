"""Verify the Alembic migration framework replaces ``create_all``.

These tests pin the acceptance criteria for issue #352: Alembic is
configured, ``init_db()`` drives ``alembic upgrade``, and the full set of
tables registered on ``Base.metadata`` appears after migration.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest
from sqlalchemy import create_engine, inspect, text

KUBETIX_API_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class _CompletedProcess:
    """Minimal stand-in for subprocess.CompletedProcess used by init_db tests."""

    stdout = b""
    stderr = b""


@pytest.fixture(scope="module")
def upgraded_db() -> str:
    """Run ``alembic upgrade head`` against a fresh SQLite file and yield its URL."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
        db_path = handle.name

    db_url = f"sqlite:///{db_path}"
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url

    try:
        subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            cwd=KUBETIX_API_DIR,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        yield db_url
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_alembic_upgrade_populates_version_table(upgraded_db: str) -> None:
    engine = create_engine(upgraded_db)
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
    finally:
        engine.dispose()

    assert row is not None, "alembic version row missing after upgrade"
    assert (
        row[0] == "0001_initial"
    ), f"unexpected head revision: {row[0]!r} (expected '0001_initial')"


def test_alembic_upgrade_creates_every_model_table(upgraded_db: str) -> None:
    """``alembic upgrade head`` must cover every table registered on Base.metadata.

    Guards against the schema-completeness regression flagged in the PR
    review: autogenerate started with three tables only and silently missed
    ``teams``, ``team_members``, ``grants``, etc.
    """
    # Importing the package populates ``Base.metadata`` with every model.
    sys.path.insert(0, KUBETIX_API_DIR)
    try:
        from kubetix_api.models import Base
    finally:
        # Clean up so other tests see a fresh import order if they re-import.
        sys.path.remove(KUBETIX_API_DIR)

    expected_tables = set(Base.metadata.tables.keys())

    engine = create_engine(upgraded_db)
    try:
        inspector = inspect(engine)
        actual_tables = set(inspector.get_table_names())
    finally:
        engine.dispose()

    missing = expected_tables - actual_tables
    assert not missing, (
        f"alembic upgrade produced a database missing tables: {sorted(missing)}. "
        f"Expected every Base.metadata table, got {sorted(actual_tables)}."
    )


def test_init_db_uses_alembic_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    """``init_db`` must invoke ``alembic upgrade head``, not ``create_all``."""
    # Lazily import inside the test so the package import cost isn't paid
    # when the module is collected and so we can stub subprocess safely.
    sys.path.insert(0, KUBETIX_API_DIR)
    from kubetix_api.database import init_db  # type: ignore[import-not-found]

    calls: list[tuple[tuple, dict]] = []

    def fake_run(args, **kwargs):
        calls.append((tuple(args), kwargs))
        return _CompletedProcess()

    try:
        monkeypatch.setattr(subprocess, "run", fake_run)

        init_db()

        assert calls, "init_db() did not invoke any subprocess"
        args, kwargs = calls[0]
        # The command may be ``python -m alembic ...`` or ``alembic ...``
        # depending on environment; we just require "alembic" in the resolved
        # command list and "upgrade"/"head" in the args, never ``create_all``.
        assert any("alembic" in str(a) for a in args), args
        assert "upgrade" in args
        assert "head" in args
        assert "create_all" not in args
        # ``cwd`` must point at the kubetix-api directory so the
        # ``alembic.ini`` discovery path resolves correctly.
        assert "cwd" in kwargs
    finally:
        sys.path.remove(KUBETIX_API_DIR)


def test_migrate_add_fk_script_removed() -> None:
    """The one-off SQLite-only migration script must be gone (issue #352)."""
    legacy_path = os.path.join(KUBETIX_API_DIR, "migrate_add_fk.py")
    assert not os.path.exists(legacy_path), (
        f"{legacy_path} should be removed now that Alembic owns the schema; "
        "its behavior must be covered by an Alembic revision + this test."
    )
