"""
Shared database setup for KubeTix API tests.

All test modules should import from here instead of creating their own engine.
This ensures a single in-memory SQLite database is used across all tests,
preventing "no such table" errors and rate-limit state leaks.
"""

import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:?cache=shared"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    poolclass=StaticPool,
)

# Threading lock to serialize writes and prevent SQLite lock contention
# during concurrent test execution.
_write_lock = threading.Lock()

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override for FastAPI's get_db dependency.

    Serializes database writes with a threading lock to prevent SQLite
    lock contention when tests run concurrent requests (e.g., concurrency
    tests that fire 10 simultaneous POSTs).
    """
    db = TestingSessionLocal()
    try:
        # Acquire write lock for the duration of the request's DB operations.
        # This ensures SQLite writes don't collide under concurrent load.
        with _write_lock:
            yield db
    finally:
        db.close()
