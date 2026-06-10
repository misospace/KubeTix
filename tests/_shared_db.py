"""
Shared database setup for KubeTix API tests.

All test modules should import from here instead of creating their own engine.
This ensures a single in-memory SQLite database is used across all tests,
preventing "no such table" errors and rate-limit state leaks.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override for FastAPI's get_db dependency."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()
