"""Database configuration and session management for KubeTix."""

import os
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------
#
# Both ``engine`` and ``SessionLocal`` are built lazily from ``DATABASE_URL``
# on first use. This avoids reading ``os.environ`` at import time, which used
# to force tests that needed a different database (or a fresh schema) to
# ``monkeypatch.setenv`` *before* importing the package and then evict the
# module from ``sys.modules`` to force a re-import. The ``reset_engine`` helper
# below lets tests drop the cached engine after mutating the environment so a
# new engine is built on the next call. It is also safe to call from
# production code paths (e.g. a startup hook) if the configuration changes
# at runtime.

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


def _default_database_url() -> str:
    """Return the configured ``DATABASE_URL`` or raise a clear ``RuntimeError``.

    Issue #276 (``[P2] Default SQLite database is unsuitable for production
    deployments``) removes the silent SQLite fallback so that misconfigured
    production deployments fail fast at startup instead of silently persisting
    data to a non-durable, single-writer SQLite file in the container's working
    directory.

    Operators must point ``DATABASE_URL`` at a real PostgreSQL instance
    (matching the bundled ``docker-compose.yml`` / Helm chart subchart) before
    starting the API. The test suite sets a temporary SQLite URL via
    ``tests/conftest.py``.
    """

    url = os.environ.get("DATABASE_URL")
    if not url or not url.strip():
        raise RuntimeError(
            "DATABASE_URL is not set. KubeTix requires an explicit database URL "
            "(e.g. postgresql+psycopg2://user:pass@host:5432/db). The unsafe "
            "SQLite fallback has been removed; see issue #276."
        )
    return url


def _build_connect_args(url: str) -> dict:
    """Return dialect-safe ``connect_args`` for ``url``.

    ``check_same_thread`` is a ``sqlite3`` driver keyword; passing it to
    psycopg2/psycopg raises ``TypeError: 'check_same_thread' is an invalid
    keyword argument for this function``. We only attach it for sqlite URLs,
    which is the only dialect the KubeTix API currently defaults to in
    tests / development. Production deployments point ``DATABASE_URL`` at
    PostgreSQL (see issue #310) and must not receive sqlite-only kwargs.
    """
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine, building it on first use."""
    global _engine
    if _engine is None:
        url = _default_database_url()
        _engine = create_engine(url, connect_args=_build_connect_args(url))
    return _engine


def get_session_factory() -> sessionmaker:
    """Return the process-wide ``sessionmaker``, building it on first use."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=get_engine()
        )
    return _SessionLocal


def reset_engine() -> None:
    """Dispose the cached engine/sessionmaker so the next access rebuilds them.

    Tests use this after mutating ``DATABASE_URL`` (via ``monkeypatch.setenv``)
    to avoid the brittle pattern of ``sys.modules.pop('kubetix_api.database')``
    followed by a forced re-import. Production code can also call this if the
    database location changes at runtime.
    """
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def get_db() -> Generator[Session, None, None]:
    """Yield a database session; close it afterwards."""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Apply Alembic migrations to bring the database to ``HEAD``.

    Replaces the previous ``Base.metadata.create_all`` flow. ``create_all``
    only creates missing tables and never alters them, so it cannot evolve an
    existing schema. With Alembic, every schema change is a versioned
    revision that supports upgrade *and* rollback.

    The Alembic invocation drives off this module's own path: the
    ``alembic.ini`` and ``migrations/`` directory live alongside
    ``kubetix_api/`` in the source tree. The path is derived from ``__file__``
    rather than user input, so there is no path-traversal surface here.
    """
    import os
    import subprocess
    import sys

    # ``os.path.dirname(__file__)`` is the kubetix_api package directory; the
    # alembic.ini and migrations/ directory live one level up (in kubetix-api/).
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config_path = os.path.join(repo_root, "alembic.ini")

    # Touched so even if ``init_db`` is the only database call the side
    # effect import is intentional rather than dead code.
    from kubetix_api.models import Base  # noqa: F401

    del Base

    # Use ``python -m alembic`` rather than a bare ``alembic`` CLI so we don't
    # depend on a PATH lookup that may not exist inside the API container.
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", config_path, "upgrade", "head"],
        cwd=repo_root,
        check=True,
    )


# ---------------------------------------------------------------------------
# Backward-compatible alias for code that imports SessionLocal directly
# ---------------------------------------------------------------------------


class _SessionLocalProxy:
    """Proxy that always delegates to the current session factory.

    After ``reset_engine()`` clears the cached ``_SessionLocal``, this proxy
    ensures that subsequent calls to ``SessionLocal()`` pick up the rebuilt
    factory instead of a stale reference to the disposed one.
    """

    def __call__(self, *args, **kwargs):
        return get_session_factory()(*args, **kwargs)


SessionLocal = _SessionLocalProxy()
