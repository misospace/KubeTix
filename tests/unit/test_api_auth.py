"""
Unit tests for KubeTix API - Authentication
Tests the FastAPI backend authentication endpoints
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import the main app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, get_password_hash


# Test database (in-memory SQLite)
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def client():
    """Create test client with fresh database."""
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create database session for tests."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)


class TestUserRegistration:
    """Tests for user registration endpoint."""
    
    def test_register_new_user(self, client):
        """Test registering a new user."""
        response = client.post(
            "/users",
            json={
                "email": "test@example.com",
                "password": "testpassword123",
                "full_name": "Test User"
            }
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
            email="test@example.com",
            hashed_password=get_password_hash("password123")
        )
        db_session.add(user)
        db_session.commit()
        
        # Try to register again
        response = client.post(
            "/users",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_register_invalid_email(self, client):
        """Test registering with invalid email."""
        response = client.post(
            "/users",
            json={
                "email": "not-an-email",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 422
    
    def test_register_missing_email(self, client):
        """Test registering without email."""
        response = client.post(
            "/users",
            json={
                "password": "testpassword123"
            }
        )
        assert response.status_code == 422
    
    def test_register_missing_password(self, client):
        """Test registering without password."""
        response = client.post(
            "/users",
            json={
                "email": "test@example.com"
            }
        )
        assert response.status_code == 422
    
    def test_register_short_password(self, client):
        """Test registering with short password."""
        response = client.post(
            "/users",
            json={
                "email": "test@example.com",
                "password": "short"
            }
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
            hashed_password=get_password_hash("testpassword123")
        )
        db_session.add(user)
        db_session.commit()
        
        # Login
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
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
            hashed_password=get_password_hash("correctpassword")
        )
        db_session.add(user)
        db_session.commit()
        
        # Login with wrong password
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()
    
    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = client.post(
            "/login",
            json={
                "email": "nonexistent@example.com",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 401
    
    def test_login_missing_email(self, client):
        """Test login without email."""
        response = client.post(
            "/login",
            json={
                "password": "testpassword123"
            }
        )
        assert response.status_code == 422
    
    def test_login_missing_password(self, client):
        """Test login without password."""
        response = client.post(
            "/login",
            json={
                "email": "test@example.com"
            }
        )
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
            "/users",
            json={
                "email": "test@example.com",
                "password": "mysecretpassword"
            }
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
