"""
Unit tests for KubeTix API - Authentication
Tests the FastAPI backend authentication endpoints
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from _shared_db import engine, TestingSessionLocal

# Import the main app
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, get_password_hash

# Test database (in-memory SQLite)


class TestUserRegistration:
    """Tests for user registration endpoint."""

    def test_register_new_user(self, client):
        """Test registering a new user."""
        response = client.post(
            "/users",
            json={
                "email": "test@example.com",
                "password": "testpassword123",
                "full_name": "Test User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"
        assert "id" in data
        assert "created_at" in data
        # Password should not be returned
        assert "password" not in data
        assert "hashed_password" not in data

    def test_register_duplicate_email(self, client, db_session):
        """Test registering with duplicate email fails."""
        # Create user first
        user = User(
            email="test@example.com", hashed_password=get_password_hash("password123")
        )
        db_session.add(user)
        db_session.commit()

        # Try to register again
        response = client.post(
            "/users", json={"email": "test@example.com", "password": "testpassword123"}
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()

    def test_register_invalid_email(self, client):
        """Test registering with invalid email."""
        response = client.post(
            "/users", json={"email": "not-an-email", "password": "testpassword123"}
        )
        assert response.status_code == 422

    def test_register_missing_email(self, client):
        """Test registering without email."""
        response = client.post("/users", json={"password": "testpassword123"})
        assert response.status_code == 422

    def test_register_missing_password(self, client):
        """Test registering without password."""
        response = client.post("/users", json={"email": "test@example.com"})
        assert response.status_code == 422

    def test_register_short_password(self, client):
        """Test registering with short password."""
        response = client.post(
            "/users", json={"email": "test@example.com", "password": "short"}
        )
        # Should accept short passwords (no validation) - but test documents behavior
        assert response.status_code in [201, 422]


class TestUserLogin:
    """Tests for user login endpoint."""

    def test_login_success(self, client, db_session):
        """Test successful login."""
        # Create user
        user = User(
            email="test@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(user)
        db_session.commit()

        # Login
        response = client.post(
            "/login", json={"email": "test@example.com", "password": "testpassword123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "test@example.com"

    def test_login_wrong_password(self, client, db_session):
        """Test login with wrong password."""
        # Create user
        user = User(
            email="test@example.com",
            hashed_password=get_password_hash("correctpassword"),
        )
        db_session.add(user)
        db_session.commit()

        # Login with wrong password
        response = client.post(
            "/login", json={"email": "test@example.com", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()

    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = client.post(
            "/login",
            json={"email": "nonexistent@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 401

    def test_login_missing_email(self, client):
        """Test login without email."""
        response = client.post("/login", json={"password": "testpassword123"})
        assert response.status_code == 422

    def test_login_missing_password(self, client):
        """Test login without password."""
        response = client.post("/login", json={"email": "test@example.com"})
        assert response.status_code == 422


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self, client):
        """Test health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestPasswordHashing:
    """Tests for password hashing functionality."""

    def test_password_not_stored_plaintext(self, client, db_session):
        """Test that passwords are not stored in plaintext."""
        response = client.post(
            "/users", json={"email": "test@example.com", "password": "mysecretpassword"}
        )
        assert response.status_code == 201

        # Check database
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        assert user.hashed_password != "mysecretpassword"
        assert user.hashed_password.startswith("$")  # bcrypt prefix

    def test_password_verification(self, db_session):
        """Test password verification works correctly."""
        from main import verify_password

        password = "testpassword123"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True
        assert verify_password("wrongpassword", hashed) is False


class TestAccessTokenLifetime:
    """Regression tests for the default JWT access token lifetime.

    Issue #157: the previous default of 7 days is far too long for an
    access token that has no refresh token or revocation mechanism beyond
    an in-memory blacklist. A stolen token must have a limited blast
    radius, so the default must remain short.
    """

    def test_access_token_default_ttl_is_short(self):
        """Default token lifetime must not exceed 1 hour."""
        from kubetix_api.auth import ACCESS_TOKEN_EXPIRE_MINUTES

        assert ACCESS_TOKEN_EXPIRE_MINUTES <= 60, (
            "ACCESS_TOKEN_EXPIRE_MINUTES=%d is too long for an access "
            "token without a refresh token or revocation mechanism"
            % ACCESS_TOKEN_EXPIRE_MINUTES
        )

    def test_access_token_default_ttl_is_not_seven_days(self):
        """Explicit regression guard for issue #157 (was 60*24*7 minutes)."""
        from kubetix_api.auth import ACCESS_TOKEN_EXPIRE_MINUTES

        assert ACCESS_TOKEN_EXPIRE_MINUTES != 60 * 24 * 7

    def test_create_access_token_uses_short_default_ttl(self):
        """A token created without an explicit expires_delta must expire
        within the configured short window."""
        from datetime import datetime, timedelta, timezone
        from kubetix_api.auth import (
            ACCESS_TOKEN_EXPIRE_MINUTES,
            create_access_token,
        )

        before = datetime.now(timezone.utc)
        token = create_access_token(data={"sub": "user@example.com"})
        # Decode without verifying signature to inspect the `exp` claim.
        from jose import jwt as jose_jwt

        payload = jose_jwt.get_unverified_claims(token)
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        lifetime = exp - before

        # Lifetime must be close to ACCESS_TOKEN_EXPIRE_MINUTES (allow a
        # generous tolerance to absorb clock skew / function latency in
        # either direction).
        expected = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        assert abs(lifetime - expected) < timedelta(seconds=10)
        # And absolute cap: must be <= 1 hour.
        assert lifetime <= timedelta(hours=1)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
