"""
Unit tests for KubeTix API - Grants
Tests the grants API endpoints
"""

import pytest
import json
from datetime import datetime, timezone, timedelta
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
    # Create user
    user = User(
        id=secrets.token_urlsafe(16),
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


class TestListGrants:
    """Tests for listing grants."""
    
    def test_list_grants_empty(self, client, auth_headers):
        """Test listing grants when none exist."""
        response = client.get("/grants", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []
    
    def test_list_grants_with_data(self, client, db_session, auth_headers, auth_token):
        """Test listing grants with data."""
        # Create grant in database
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        
        # List grants
        response = client.get("/grants", headers=auth_headers)
        assert response.status_code == 200
        grants = response.json()
        assert len(grants) == 1
        assert grants[0]["cluster_name"] == "test-cluster"
    
    def test_list_grants_unauthorized(self, client):
        """Test listing grants without authentication."""
        response = client.get("/grants")
        assert response.status_code == 401
    
    def test_list_grants_expired_not_shown(self, client, db_session, auth_headers, auth_token):
        """Test that expired grants are not listed."""
        # Create expired grant
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
        
        # List grants - expired should not appear
        response = client.get("/grants", headers=auth_headers)
        assert response.status_code == 200
        grants = response.json()
        assert len(grants) == 0
    
    def test_list_grants_revoked_not_shown(self, client, db_session, auth_headers, auth_token):
        """Test that revoked grants are not listed."""
        # Create revoked grant
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
        
        # List grants - revoked should not appear
        response = client.get("/grants", headers=auth_headers)
        assert response.status_code == 200
        grants = response.json()
        assert len(grants) == 0


class TestCreateGrants:
    """Tests for creating grants."""
    
    def test_create_grant_minimal(self, client, auth_headers, monkeypatch):
        """Test creating a grant with minimal parameters."""
        # Mock kubeconfig file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view"
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 201
        data = response.json()
        assert data["cluster_name"] == "test-cluster"
        assert data["role"] == "view"
        assert "id" in data
        assert "expires_at" in data
    
    def test_create_grant_with_namespace(self, client, auth_headers, monkeypatch):
        """Test creating a grant with namespace."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "namespace": "production",
                "role": "edit"
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 201
        data = response.json()
        assert data["namespace"] == "production"
    
    def test_create_grant_invalid_role(self, client, auth_headers, monkeypatch):
        """Test creating a grant with invalid role."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "super-admin"  # Invalid role
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
        assert "invalid role" in response.json()["detail"].lower()
    
    def test_create_grant_expiry_too_short(self, client, auth_headers, monkeypatch):
        """Test creating a grant with expiry too short."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view",
                "expiry_hours": 0  # Too short
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
    
    def test_create_grant_expiry_too_long(self, client, auth_headers, monkeypatch):
        """Test creating a grant with expiry too long."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view",
                "expiry_hours": 1000  # Too long
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
    
    def test_create_grant_missing_cluster_name(self, client, auth_headers):
        """Test creating a grant without cluster name."""
        response = client.post(
            "/grants",
            json={
                "role": "view"
            },
            headers=auth_headers
        )
        assert response.status_code == 422
    
    def test_create_grant_unauthorized(self, client):
        """Test creating a grant without authentication."""
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view"
            }
        )
        assert response.status_code == 401


class TestRevokeGrants:
    """Tests for revoking grants."""
    
    def test_revoke_grant_success(self, client, db_session, auth_headers, auth_token):
        """Test successfully revoking a grant."""
        # Create grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Revoke grant
        response = client.delete(f"/grants/{grant_id}", headers=auth_headers)
        assert response.status_code == 204
        
        # Verify grant is revoked
        grant = db_session.query(Grant).filter(Grant.id == grant_id).first()
        assert grant.revoked is True
    
    def test_revoke_nonexistent_grant(self, client, auth_headers):
        """Test revoking a nonexistent grant."""
        response = client.delete("/grants/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404
    
    def test_revoke_grant_already_revoked(self, client, db_session, auth_headers, auth_token):
        """Test revoking an already revoked grant."""
        # Create revoked grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted-data",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked=True
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Try to revoke again
        response = client.delete(f"/grants/{grant_id}", headers=auth_headers)
        # Should still return 204 (idempotent)
        assert response.status_code == 204


class TestDownloadGrants:
    """Tests for downloading grants."""
    
    def test_download_grant_success(self, client, db_session, auth_headers, auth_token, monkeypatch):
        """Test successfully downloading a grant."""
        import base64
        
        # Create kubeconfig file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\nclusters: []\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        kubeconfig_content = open(kubeconfig_path).read()
        encrypted = base64.b64encode(kubeconfig_content.encode()).decode()
        
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
        assert "kubeconfig" in data
        assert "apiVersion" in data["kubeconfig"]
    
    def test_download_revoked_grant(self, client, db_session, auth_headers, auth_token, monkeypatch):
        """Test downloading a revoked grant fails."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create revoked grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked=True
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Try to download
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
        assert "revoked" in response.json()["detail"].lower()
    
    def test_download_expired_grant(self, client, db_session, auth_headers, auth_token, monkeypatch):
        """Test downloading an expired grant fails."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create expired grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)  # Expired
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id
        
        # Try to download
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)
        
        os.unlink(kubeconfig_path)
        
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
