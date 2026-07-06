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
from _shared_db import engine, TestingSessionLocal
import secrets
import os

os.environ["KUBECONFIG_ENCRYPTION_KEY"] = "NJGBGddzqA6EVxj4Ld4yDGOmBi2srREevbPY7Z7JNso="
import tempfile

# Import the main app
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, Grant, get_password_hash
from cryptography.fernet import Fernet


# Fernet encryption helper for creating test encrypted kubeconfig grants
def _fernet_encrypt(data: str) -> str:
    key = os.environ.get("KUBECONFIG_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("KUBECONFIG_ENCRYPTION_KEY not set")
    return Fernet(key.encode()).encrypt(data.encode()).decode()


# Test database (in-memory SQLite)


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
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
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

    def test_list_grants_expired_not_shown(
        self, client, db_session, auth_headers, auth_token
    ):
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
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # Expired
        )
        db_session.add(grant)
        db_session.commit()

        # List grants - expired should not appear
        response = client.get("/grants", headers=auth_headers)
        assert response.status_code == 200
        grants = response.json()
        assert len(grants) == 0

    def test_list_grants_revoked_not_shown(
        self, client, db_session, auth_headers, auth_token
    ):
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
            revoked=True,
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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        response = client.post(
            "/grants",
            json={"cluster_name": "test-cluster", "role": "view"},
            headers=auth_headers,
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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "namespace": "production",
                "role": "edit",
            },
            headers=auth_headers,
        )

        os.unlink(kubeconfig_path)

        assert response.status_code == 201
        data = response.json()
        assert data["namespace"] == "production"

    def test_create_grant_invalid_role(self, client, auth_headers, monkeypatch):
        """Test creating a grant with invalid role."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "super-admin",  # Invalid role
            },
            headers=auth_headers,
        )

        os.unlink(kubeconfig_path)

        assert response.status_code == 422
        assert any("role" in str(err).lower() for err in response.json()["detail"])

    def test_create_grant_expiry_too_short(self, client, auth_headers, monkeypatch):
        """Test creating a grant with expiry too short."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view",
                "expiry_hours": 0,  # Too short
            },
            headers=auth_headers,
        )

        os.unlink(kubeconfig_path)

        assert response.status_code == 422

    def test_create_grant_expiry_too_long(self, client, auth_headers, monkeypatch):
        """Test creating a grant with expiry too long."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view",
                "expiry_hours": 1000,  # Too long
            },
            headers=auth_headers,
        )

        os.unlink(kubeconfig_path)

        assert response.status_code == 422

    def test_create_grant_missing_cluster_name(self, client, auth_headers):
        """Test creating a grant without cluster name."""
        response = client.post("/grants", json={"role": "view"}, headers=auth_headers)
        assert response.status_code == 422

    def test_create_grant_unauthorized(self, client):
        """Test creating a grant without authentication."""
        response = client.post(
            "/grants", json={"cluster_name": "test-cluster", "role": "view"}
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
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id

        # Revoke grant
        response = client.delete(f"/grants/{grant_id}", headers=auth_headers)
        assert response.status_code == 204

        # Verify grant is revoked — re-query from the same session
        db_session.expire_all()
        grant = db_session.query(Grant).filter(Grant.id == grant_id).first()
        assert grant.revoked is True

    def test_revoke_nonexistent_grant(self, client, auth_headers):
        """Test revoking a nonexistent grant."""
        response = client.delete("/grants/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404

    def test_revoke_grant_already_revoked(
        self, client, db_session, auth_headers, auth_token
    ):
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
            revoked=True,
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

    def test_download_grant_success(
        self, client, db_session, auth_headers, auth_token, monkeypatch
    ):
        """Test successfully downloading a grant."""
        from kubetix_api.grants import _get_fernet

        # Set fixed encryption key so test and API use the same key
        monkeypatch.setenv(
            "KUBECONFIG_ENCRYPTION_KEY", "T2KBewlnH_vRDWCBGLdnrcBciZBq497CaE0mGVZdMs0="
        )

        # Create kubeconfig file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\nclusters: []\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        # Create grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()
        kubeconfig_content = open(kubeconfig_path).read()
        fernet = _get_fernet()
        encrypted = fernet.encrypt(kubeconfig_content.encode()).decode()

        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig=encrypted,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
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

    def test_download_revoked_grant(
        self, client, db_session, auth_headers, auth_token, monkeypatch
    ):
        """Test downloading a revoked grant fails."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
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
            revoked=True,
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id

        # Try to download
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)

        os.unlink(kubeconfig_path)

        assert response.status_code == 400
        assert "revoked" in response.json()["detail"].lower()

    def test_download_expired_grant(
        self, client, db_session, auth_headers, auth_token, monkeypatch
    ):
        """Test downloading an expired grant fails."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
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
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # Expired
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id

        # Try to download
        response = client.get(f"/grants/{grant_id}/download", headers=auth_headers)

        os.unlink(kubeconfig_path)

        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()


class TestEncryptionKeyRequired:
    """Tests that KUBECONFIG_ENCRYPTION_KEY is required."""

    def test_get_fernet_raises_when_key_not_set(self, monkeypatch):
        """Test that _get_fernet raises ValueError when key is not configured."""
        from kubetix_api.grants import _get_fernet

        monkeypatch.delenv("KUBECONFIG_ENCRYPTION_KEY", raising=False)
        with pytest.raises(ValueError, match="KUBECONFIG_ENCRYPTION_KEY must be set"):
            _get_fernet()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
