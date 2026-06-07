"""
Unit tests for KubeTix API - Download Grant endpoint
Tests the /grants/{grant_id}/download endpoint
"""

import pytest
import json
# Fernet encryption for test fixtures (matches API encryption)
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta

# Fixed Fernet key for consistent test data (matches API default behavior)
_TEST_FERNET_KEY = b"NJGBGddzqA6EVxj4Ld4yDGOmBi2srREevbPY7Z7JNso="
_test_fernet = Fernet(_TEST_FERNET_KEY)

def _fernet_encrypt(data):
    """Encrypt data for test fixtures using the same Fernet scheme as the API."""
    return _test_fernet.encrypt(data.encode()).decode()
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import secrets
import os
import tempfile

# Import the main app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, Grant, get_password_hash


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


@pytest.fixture(scope="function")
def auth_token(client, db_session):
    """Create user and return auth token."""
    user = User(
        id=secrets.token_urlsafe(16),
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123")
    )
    db_session.add(user)
    db_session.commit()
    
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


@pytest.fixture(scope="function")
def other_user(db_session):
    """Create a different user for cross-user tests."""
    user = User(
        id=secrets.token_urlsafe(16),
        email="other@example.com",
        hashed_password=get_password_hash("otherpassword123")
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture(scope="function")
def other_token(client, db_session, other_user):
    """Create token for the other user."""
    response = client.post(
        "/login",
        json={
            "email": "other@example.com",
            "password": "otherpassword123"
        }
    )
    return response.json()["access_token"]


@pytest.fixture(scope="function")
def other_headers(other_token):
    """Return authorization headers for the other user."""
    return {"Authorization": f"Bearer {other_token}"}


class TestDownloadGrant:
    """Tests for downloading grants."""
    
    def test_download_grant_success(self, client, db_session, auth_headers, monkeypatch):
        """Test successfully downloading a grant with valid kubeconfig."""
        # Create kubeconfig file
        kubeconfig_content = "apiVersion: v1\nkind: Config\nclusters:\n  - name: test-cluster\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write(kubeconfig_content)
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        encrypted = _fernet_encrypt(kubeconfig_content)
        
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig=encrypted,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Download grant
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == grant_id
        assert data["cluster_name"] == "test-cluster"
        assert data["role"] == "view"
        assert data["namespace"] == "default"
        assert "kubeconfig" in data
        assert "apiVersion" in data["kubeconfig"]
    
    def test_download_grant_not_found(self, client, auth_headers):
        """Test downloading a nonexistent grant returns 404."""
        response = client.get("/grants/nonexistent-id-12345/download", headers=auth_headers)
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_download_grant_wrong_user(self, client, db_session, other_headers, monkeypatch):
        """Test that a user cannot download another user's grant (403)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create grant for original user
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="other-cluster",
            namespace="production",
            role="admin",
            encrypted_kubeconfig="encrypted-kubeconfig-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Try to download as different user
        response = client.get(f"/grants/{grant_id}/download", headers=other_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 403
        assert "not authorized" in response.json()["detail"].lower()
    
    def test_download_revoked_grant(self, client, db_session, auth_headers, monkeypatch):
        """Test downloading a revoked grant returns 400."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="revoked-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked=True
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
        assert "revoked" in response.json()["detail"].lower()
    
    def test_download_expired_grant(self, client, db_session, auth_headers, monkeypatch):
        """Test downloading an expired grant returns 400."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="expired-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)  # Expired
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()
    
    def test_download_grant_unauthorized(self, client):
        """Test downloading a grant without authentication returns 401."""
        response = client.get("/grants/some-id/download")
        assert response.status_code == 401
    
    def test_download_grant_with_namespace(self, client, db_session, auth_headers, monkeypatch):
        """Test downloading a grant with a specific namespace."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="ns-cluster",
            namespace="production",
            role="edit",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 200
        data = response.json()
        assert data["namespace"] == "production"
        assert data["role"] == "edit"
    
    def test_download_grant_admin_role(self, client, db_session, auth_headers, monkeypatch):
        """Test downloading a grant with admin role."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="admin-cluster",
            namespace="kube-system",
            role="admin",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "admin"
    
    def test_download_grant_response_fields(self, client, db_session, auth_headers, monkeypatch):
        """Test that download response contains all expected fields."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="fields-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 200
        data = response.json()
        expected_fields = {"id", "cluster_name", "namespace", "role", "expires_at", "kubeconfig"}
        for field in expected_fields:
            assert field in data, f"Missing field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
