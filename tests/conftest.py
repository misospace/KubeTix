"""
Shared pytest fixtures for KubeTix API tests.

Provides a single in-memory SQLite database and resets state between tests
to prevent fixture isolation issues (no such table), rate-limit leaks, and
dependency-override conflicts across test modules.
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure kubetix-api is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, get_password_hash
from _shared_db import engine, TestingSessionLocal, override_get_db

# Apply the dependency override once for all tests
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session")
def _setup_tables():
    """Create database tables once for the entire test session."""
    Base.metadata.create_all(bind=engine)
    yield
    # Tables persist for the session


@pytest.fixture(scope="function")
def client(_setup_tables):
    """Test client with a clean database per test function.

    Drops and recreates all tables before each test to ensure fixture
    isolation — no "no such table" errors across modules.
    Also resets slowapi rate limiter state between tests.
    """
    # Reset: drop then recreate tables for a fresh state
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Reset slowapi rate limiter state if available
    if hasattr(app.state, "limiter") and app.state.limiter is not None:
        if hasattr(app.state.limiter, "storage"):
            try:
                app.state.limiter.storage.clear()
            except Exception:
                pass

    yield TestClient(app)

    # Final cleanup
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(_setup_tables):
    """Database session for tests that need direct DB access."""
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()


import os

@pytest.fixture(scope="function")
def db(db_session):
    """Alias for db_session (some test files use 'db' instead of 'db_session')."""
    return db_session


# Skip rate-limiting tests when TESTING mode is enabled (rate limiting is disabled)
def pytest_collection_modifyitems(config, items):
    if os.environ.get("TESTING"):
        skip_rate_limit = pytest.mark.skip(reason="rate limiting disabled in TESTING mode")
        for item in items:
            if "rate_limit" in item.nodeid or "RateLimit" in item.name:
                item.add_marker(skip_rate_limit)


# Additional fixtures needed by audit log and download grant tests
@pytest.fixture(scope="function")
def admin_user(db):
    """Create an admin user."""
    from main import create_access_token
    user = User(
        id="admin-user-123",
        email="admin@example.com",
        hashed_password=get_password_hash("adminpassword123"),
        is_admin=True
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture(scope="function")
def admin_token(db, admin_user):
    from main import create_access_token
    from datetime import timedelta
    token = create_access_token(data={"sub": admin_user.email}, expires_delta=timedelta(minutes=60*24*7))
    return token


@pytest.fixture(scope="function")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="function")
def other_user(db):
    user = User(
        id="other-user-456",
        email="other@example.com",
        hashed_password=get_password_hash("otherpassword123")
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture(scope="function")
def other_token(db, other_user):
    from main import create_access_token
    from datetime import timedelta
    token = create_access_token(data={"sub": other_user.email}, expires_delta=timedelta(minutes=60*24*7))
    return token


@pytest.fixture(scope="function")
def other_headers(other_token):
    return {"Authorization": f"Bearer {other_token}"}


@pytest.fixture(scope="function")
def auth_token(client, db_session):
    """Create user and return auth token."""
    # Create user
    user = User(
        id="test-user-123",
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123")
    )
    db_session.add(user)
    db_session.commit()

    # Login to get token
    response = client.post(
        "/login",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    return response.json()["access_token"]


@pytest.fixture(scope="function")
def auth_headers(auth_token):
    """Return authorization headers."""
    return {"Authorization": f"Bearer {auth_token}"}
