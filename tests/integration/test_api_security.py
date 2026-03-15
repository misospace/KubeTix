"""
Security tests for KubeTix API
Tests input validation, SQL injection prevention, and security measures
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


# Test database
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


class TestSQLInjectionPrevention:
    """Tests for SQL injection prevention."""
    
    def test_email_field_sql_injection(self, client):
        """Test that SQL injection in email is prevented."""
        malicious_emails = [
            "test' OR '1'='1",
            "test\" OR \"1\"=\"1",
            "test'; DROP TABLE users;--",
            "test\"; DROP TABLE users;--",
            "admin'--",
            "test@email.com' UNION SELECT * FROM users--"
        ]
        
        for email in malicious_emails:
            response = client.post(
                "/users",
                json={
                    "email": email,
                    "password": "testpassword123"
                }
            )
            # Should either succeed (if email is valid format) or fail with validation error
            # Should NOT cause server error or SQL syntax error
            assert response.status_code in [201, 400, 422], f"SQL injection possible with email: {email}"
    
    def test_login_sql_injection(self, client, db_session):
        """Test SQL injection in login endpoint."""
        # Create user first
        user = User(
            email="normal@example.com",
            hashed_password=get_password_hash("password123")
        )
        db_session.add(user)
        db_session.commit()
        
        # Try SQL injection in password field
        malicious_passwords = [
            "' OR '1'='1",
            "' OR ''='",
            "admin'--",
            "' OR '1'='1' --"
        ]
        
        for password in malicious_passwords:
            response = client.post(
                "/login",
                json={
                    "email": "normal@example.com",
                    "password": password
                }
            )
            # Should fail with auth error, not server error
            assert response.status_code == 401
    
    def test_cluster_name_sql_injection(self, client, auth_headers, monkeypatch):
        """Test SQL injection in cluster name field."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        malicious_names = [
            "test'; DROP TABLE grants;--",
            "test\"; DROP TABLE grants;--",
            "test' UNION SELECT * FROM grants--"
        ]
        
        for cluster_name in malicious_names:
            response = client.post(
                "/grants",
                json={
                    "cluster_name": cluster_name,
                    "role": "view"
                },
                headers=auth_headers
            )
            # Should succeed or fail with validation, not SQL error
            assert response.status_code in [201, 400, 422], f"SQL injection possible with cluster_name: {cluster_name}"
        
        os.unlink(kubeconfig_path)


class TestInputValidation:
    """Tests for input validation."""
    
    def test_email_format_validation(self, client):
        """Test email format validation."""
        invalid_emails = [
            "",
            "notanemail",
            "@example.com",
            "test@",
            "test@.com",
            "test@.com.",
            "test@.co.uk",
            "test..test@example.com"
        ]
        
        for email in invalid_emails:
            response = client.post(
                "/users",
                json={
                    "email": email,
                    "password": "testpassword123"
                }
            )
            assert response.status_code == 422, f"Should reject invalid email: {email}"
    
    def test_email_length_validation(self, client):
        """Test email length validation."""
        # Create very long email
        long_email = "a" * 200 + "@example.com"
        response = client.post(
            "/users",
            json={
                "email": long_email,
                "password": "testpassword123"
            }
        )
        # Pydantic should handle this
        assert response.status_code in [201, 422]
    
    def test_cluster_name_length(self, client, auth_headers, monkeypatch):
        """Test cluster name length validation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Very long cluster name
        long_name = "a" * 300
        response = client.post(
            "/grants",
            json={
                "cluster_name": long_name,
                "role": "view"
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        # Should be handled gracefully
        assert response.status_code in [201, 400, 422]
    
    def test_namespace_name_validation(self, client, auth_headers, monkeypatch):
        """Test namespace name validation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Test with various namespace formats
        namespaces = [
            "default",
            "kube-system",
            "prod",
            "prod-us-east-1",
            "team/a",
            "../../../etc/passwd",
            "${{malicious}}"
        ]
        
        for ns in namespaces:
            response = client.post(
                "/grants",
                json={
                    "cluster_name": "test",
                    "namespace": ns,
                    "role": "view"
                },
                headers=auth_headers
            )
            # Should accept or reject gracefully
            assert response.status_code in [201, 400, 422]
        
        os.unlink(kubeconfig_path)


class TestAuthenticationSecurity:
    """Tests for authentication security."""
    
    def test_invalid_token_format(self, client):
        """Test various invalid token formats."""
        invalid_tokens = [
            "",
            "not-a-token",
            "Bearer",
            "Bearer ",
            "invalid.format.token",
            "fake-token"
        ]
        
        for token in invalid_tokens:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = client.get("/grants", headers=headers)
            assert response.status_code == 401
    
    def test_token_without_bearer_prefix(self, client, auth_token):
        """Test token without Bearer prefix."""
        headers = {"Authorization": auth_token}
        response = client.get("/grants", headers=headers)
        # Should fail without Bearer prefix
        assert response.status_code == 401
    
    def test_expired_token_handling(self, client):
        """Test handling of expired tokens."""
        # Create an obviously expired token
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxNjAwMDAwMDAwfQ.invalid"
        
        response = client.get(
            "/grants",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401


class TestAuthorizationSecurity:
    """Tests for authorization security."""
    
    def test_user_cannot_access_other_user_grants(self, client, db_session):
        """Test that users can't access other users' grants."""
        # Create two users
        user1 = User(
            id=secrets.token_urlsafe(16),
            email="user1@example.com",
            hashed_password=get_password_hash("password123")
        )
        user2 = User(
            id=secrets.token_urlsafe(16),
            email="user2@example.com",
            hashed_password=get_password_hash("password123")
        )
        db_session.add(user1)
        db_session.add(user2)
        db_session.commit()
        
        # Login as user1
        response = client.post(
            "/login",
            json={
                "email": "user1@example.com",
                "password": "password123"
            }
        )
        user1_token = response.json()["access_token"]
        
        # Create grant for user1
        import base64
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        
        os.environ["KUBECONFIG"] = kubeconfig_path
        
        response = client.post(
            "/grants",
            json={
                "cluster_name": "user1-cluster",
                "role": "view"
            },
            headers={"Authorization": f"Bearer {user1_token}"}
        )
        
        os.unlink(kubeconfig_path)
        
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]
        
        # Create grant for user2 in database
        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user2.id,
            cluster_name="user2-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db_session.add(grant)
        db_session.commit()
        
        # User1 tries to access User2's grant
        response = client.get(
            f"/grants/{grant.id}/download",
            headers={"Authorization": f"Bearer {user1_token}"}
        )
        
        # Should be forbidden or not found
        assert response.status_code in [403, 404]


class TestRateLimiting:
    """Tests for rate limiting (when implemented)."""
    
    def test_multiple_login_attempts(self, client, db_session):
        """Test multiple failed login attempts."""
        # Create user
        user = User(
            email="test@example.com",
            hashed_password=get_password_hash("correctpassword")
        )
        db_session.add(user)
        db_session.commit()
        
        # Try multiple wrong passwords
        for i in range(10):
            response = client.post(
                "/login",
                json={
                    "email": "test@example.com",
                    "password": "wrongpassword"
                }
            )
            assert response.status_code == 401
        
        # Note: Rate limiting not yet implemented
        # This test documents expected behavior


class TestDataLeakage:
    """Tests to ensure sensitive data is not leaked."""
    
    def test_password_not_in_response(self, client):
        """Test that passwords are not returned in responses."""
        response = client.post(
            "/users",
            json={
                "email": "test@example.com",
                "password": "secretpassword123"
            }
        )
        
        data = response.json()
        
        # Password should not be in response
        assert "password" not in data
        assert "hashed_password" not in data
        assert "secretpassword123" not in str(data)
    
    def test_grant_encrypted_in_response(self, client, db_session, auth_headers, auth_token, monkeypatch):
        """Test that kubeconfig is encrypted in responses."""
        import base64
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            kubeconfig_content = "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://prod.example.com\nusers:\n- name: admin\n  user:\n    token: super-secret-token"
            f.write(kubeconfig_content)
            kubeconfig_path = f.name
        
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        
        # Create grant
        response = client.post(
            "/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view"
            },
            headers=auth_headers
        )
        
        os.unlink(kubeconfig_path)
        
        # List grants - should not include raw kubeconfig
        response = client.get("/grants", headers=auth_headers)
        data = response.json()
        
        for grant in data:
            if "kubeconfig" in grant:
                # If kubeconfig is in list response, it should be encrypted
                assert "super-secret-token" not in grant["kubeconfig"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
