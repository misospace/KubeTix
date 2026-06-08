"""
Unit tests for KubeTix API - Download Grant endpoint
Tests the /grants/{grant_id}/download endpoint
"""

import pytest
import json
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta
import secrets
import os
import tempfile
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from pathlib import Path

# Set encryption key before importing main
os.environ["KUBECONFIG_ENCRYPTION_KEY"] = "NJGBGddzqA6EVxj4Ld4yDGOmBi2srREevbPY7Z7JNso="

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "kubetix-api"))
from main import app, Base, get_db, User, Grant, get_password_hash, create_access_token

# Test database (in-memory SQLite)
_TEST_DB_URL = f"sqlite:///:memory:?dbname=download_grant_{secrets.token_hex(4)}"
_engine = create_engine(_TEST_DB_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
_TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

def _override_get_db():
    try:
        db = _TestingSessionLocal()
        yield db
    finally:
        db.close()

_test_fernet = Fernet(b"NJGBGddzqA6EVxj4Ld4yDGOmBi2srREevbPY7Z7JNso=")
def _fernet_encrypt(data):
    return _test_fernet.encrypt(data.encode()).decode()


@pytest.fixture(autouse=True)
def _setup_test_db():
    """Ensure test DB override is set for each test."""
    app.dependency_overrides[get_db] = _override_get_db
    yield
    if get_db in app.dependency_overrides:
        del app.dependency_overrides[get_db]


@pytest.fixture(scope="function")
def db():
    """Create database tables for the test."""
    Base.metadata.create_all(bind=_engine)
    yield _TestingSessionLocal()
    Base.metadata.drop_all(bind=_engine)


@pytest.fixture(scope="function")
def client():
    """Create test client."""
    yield TestClient(app)


@pytest.fixture(scope="function")
def auth_token(db):
    """Create user and return auth token (bypasses login endpoint)."""
    user = User(
        id=secrets.token_urlsafe(16),
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123")
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=60 * 24 * 7)
    )
    return token


@pytest.fixture(scope="function")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(scope="function")
def other_user(db):
    user = User(
        id=secrets.token_urlsafe(16),
        email="other@example.com",
        hashed_password=get_password_hash("otherpassword123")
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture(scope="function")
def other_token(db, other_user):
    token = create_access_token(
        data={"sub": other_user.email},
        expires_delta=timedelta(minutes=60 * 24 * 7)
    )
    return token


@pytest.fixture(scope="function")
def other_headers(other_token):
    return {"Authorization": f"Bearer {other_token}"}


class TestDownloadGrant:
    """Tests for downloading grants."""
    
    def test_download_grant_success(self, client, db, auth_headers, monkeypatch):
        kubeconfig_content = "apiVersion: v1\nkind: Config\nclusters:\n  - name: test-cluster\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write(kubeconfig_content)
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        encrypted = _fernet_encrypt(kubeconfig_content)
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="test-cluster", namespace="default", role="view",
            encrypted_kubeconfig=encrypted,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(grant); db.commit()
        grant_id = grant.id
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
        response = client.get("/grants/nonexistent-id-12345/download", headers=auth_headers)
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_download_grant_wrong_user(self, client, db, other_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        test_user = User(
            id=secrets.token_urlsafe(16),
            email="test@example.com", hashed_password=get_password_hash("testpassword123")
        )
        db.add(test_user); db.commit()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=test_user.id,
            cluster_name="other-cluster", namespace="production", role="admin",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(grant); db.commit()
        grant_id = grant.id
        response = client.get(f"/grants/{grant_id}/download", headers=other_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 403
        assert "not authorized" in response.json()["detail"].lower()
    
    def test_download_revoked_grant(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="revoked-cluster", namespace="default", role="view",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1), revoked=True
        )
        db.add(grant); db.commit()
        response = client.get(f"/grants/{grant.id}/download", headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 400
        assert "revoked" in response.json()["detail"].lower()
    
    def test_download_expired_grant(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="expired-cluster", namespace="default", role="view",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        db.add(grant); db.commit()
        response = client.get(f"/grants/{grant.id}/download", headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()
    
    def test_download_grant_unauthorized(self, client):
        response = client.get("/grants/some-id/download")
        assert response.status_code == 401
    
    def test_download_grant_with_namespace(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="ns-cluster", namespace="production", role="edit",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(grant); db.commit()
        response = client.get(f"/grants/{grant.id}/download", headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 200
        data = response.json()
        assert data["namespace"] == "production"
        assert data["role"] == "edit"
    
    def test_download_grant_admin_role(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="admin-cluster", namespace="kube-system", role="admin",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(grant); db.commit()
        response = client.get(f"/grants/{grant.id}/download", headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "admin"
    
    def test_download_grant_response_fields(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        user = db.query(User).filter(User.email == "test@example.com").first()
        grant = Grant(
            id=secrets.token_urlsafe(16), user_id=user.id,
            cluster_name="fields-cluster", namespace="default", role="view",
            encrypted_kubeconfig=_fernet_encrypt("apiVersion: v1\nkind: Config\n"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(grant); db.commit()
        response = client.get(f"/grants/{grant.id}/download", headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 200
        data = response.json()
        expected_fields = {"id", "cluster_name", "namespace", "role", "expires_at", "kubeconfig"}
        for field in expected_fields:
            assert field in data, f"Missing field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
