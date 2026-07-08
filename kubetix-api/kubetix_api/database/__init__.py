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
    return os.environ.get("DATABASE_URL") or "sqlite:///./kubetix.db"


def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine, building it on first use."""
    global _engine
    if _engine is None:
        _engine = create_engine(
            _default_database_url(),
            connect_args={"check_same_thread": False},
        )
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
    """Create all tables defined in kubetix_api.models."""
    from kubetix_api.models import Base  # noqa: F401

    Base.metadata.create_all(bind=get_engine())


# ---------------------------------------------------------------------------
# Backward-compatible alias for code that imports SessionLocal directly
# ---------------------------------------------------------------------------

SessionLocal = get_session_factory()
