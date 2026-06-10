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

# Fernet encryption helper for tests that need to create encrypted kubeconfig grants
from cryptography.fernet import Fernet


def _fernet_encrypt(data: str) -> str:
    """Encrypt data using Fernet symmetric encryption (key from env)."""
    key = os.environ.get("KUBECONFIG_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("KUBECONFIG_ENCRYPTION_KEY not set for _fernet_encrypt")
    return Fernet(key.encode()).encrypt(data.encode()).decode()


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

    # Reset slowapi rate limiter state (clears all internal dicts)
    _reset_rate_limiter()

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
@pytest.fixture(scope="function")
def test_user(db):
    """Create a regular (non-admin) test user."""
    user = User(
        id="test-user-123",
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123"),
    )
    db.add(user)
    db.commit()
    return user



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


def _reset_rate_limiter():
    """Reset slowapi rate limiter storage to prevent cross-test leaks.

    The `limits` MemoryStorage uses multiple dicts (storage, expirations, events, locks).
    Calling `.clear(key)` only removes one key; we need to clear all entries.
    """
    if hasattr(app.state, "limiter") and app.state.limiter is not None:
        st = getattr(app.state.limiter, "_storage", None)
        if st is not None:
            try:
                # Clear all internal storage dicts (limits.MemoryStorage internals)
                st.storage.clear()
                st.expirations.clear()
                st.events.clear()
                if hasattr(st, "locks"):
                    st.locks.clear()
            except Exception:
                pass


@pytest.fixture(scope="function")
def auth_token(client, db_session):
    """Create user and return auth token.

    Resets the rate limiter before login to prevent cross-test rate limit leaks.
    Retries once if rate-limited on first attempt.
    """
    # Create user
    user = User(
        id="test-user-123",
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123")
    )
    db_session.add(user)
    db_session.commit()

    # Login to get token — reset rate limiter first, retry once if rate-limited
    _reset_rate_limiter()
    response = client.post(
        "/login",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    data = response.json()
    if response.status_code == 429 or "access_token" not in data:
        # Rate-limited; reset and retry once
        _reset_rate_limiter()
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        data = response.json()
    return data["access_token"]


@pytest.fixture(scope="function")
def auth_headers(auth_token):
    """Return authorization headers."""
    return {"Authorization": f"Bearer {auth_token}"}
