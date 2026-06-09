"""
End-to-End Tests for KubeTix
Tests the full deployment using kind cluster
"""

import pytest
import subprocess
import time
import os
import tempfile
import shutil
from pathlib import Path
import requests
from typing import Optional


# Configuration
API_URL = "http://localhost:8000"


def wait_for_service_ready(url: str, timeout: int = 120):
    """Wait for API service to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f"{url}/health", timeout=5)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)

    raise TimeoutError(f"Service not ready after {timeout}s")


class TestKubeTixE2E:
    """End-to-end tests for KubeTix."""

    @pytest.fixture(scope="class", autouse=True)
    def wait_for_api(self):
        """Wait for the already-deployed API to be ready."""
        wait_for_service_ready(API_URL, timeout=60)
        yield API_URL

    @pytest.fixture(scope="class")
    def kubeconfig(self):
        """Generate test kubeconfig."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.kubeconfig') as f:
            kubeconfig_path = f.name

        default_kubeconfig = Path.home() / ".kube" / "config"
        if default_kubeconfig.exists():
            shutil.copy(default_kubeconfig, kubeconfig_path)
        else:
            os.environ["KUBECONFIG"] = kubeconfig_path

        yield kubeconfig_path

        if os.path.exists(kubeconfig_path):
            os.unlink(kubeconfig_path)

    def test_01_api_health(self, wait_for_api):
        """Test API health endpoint."""
        response = requests.get(f"{wait_for_api}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_02_user_registration(self, wait_for_api):
        """Test user registration."""
        response = requests.post(
            f"{wait_for_api}/users",
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

    def test_03_user_login(self, wait_for_api):
        """Test user login and JWT token."""
        requests.post(
            f"{wait_for_api}/users",
            json={
                "email": "login-test@example.com",
                "password": "testpassword123"
            }
        )

        response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "login-test@example.com",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "login-test@example.com"

    def test_04_create_grant(self, wait_for_api, kubeconfig):
        """Test creating a grant."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "test-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 4
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["cluster_name"] == "test-cluster"
        assert data["namespace"] == "default"
        assert data["role"] == "view"
        assert "id" in data
        assert "expires_at" in data
        assert not data["revoked"]

    def test_05_list_grants(self, wait_for_api, kubeconfig):
        """Test listing grants."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.get(
            f"{wait_for_api}/grants",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        grants = response.json()
        assert isinstance(grants, list)

    def test_06_download_grant(self, wait_for_api, kubeconfig):
        """Test downloading a grant."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        create_response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "download-test-cluster",
                "namespace": "test-ns",
                "role": "edit",
                "expiry_hours": 2
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        grant_id = create_response.json()["id"]

        response = requests.get(
            f"{wait_for_api}/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cluster_name"] == "download-test-cluster"
        assert data["namespace"] == "test-ns"
        assert data["role"] == "edit"
        assert "kubeconfig" in data
        assert len(data["kubeconfig"]) > 0

    def test_07_revoke_grant(self, wait_for_api, kubeconfig):
        """Test revoking a grant."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        create_response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "revoke-test-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 1
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        grant_id = create_response.json()["id"]

        response = requests.delete(
            f"{wait_for_api}/grants/{grant_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 204

        response = requests.get(
            f"{wait_for_api}/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
        assert "revoked" in response.json().get("detail", "").lower()

    def test_08_audit_log(self, wait_for_api, kubeconfig):
        """Test audit logging."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.get(
            f"{wait_for_api}/audit",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)

    def test_09_invalid_token(self, wait_for_api):
        """Test invalid token handling."""
        response = requests.get(
            f"{wait_for_api}/grants",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401

    def test_10_unauthorized_access(self, wait_for_api):
        """Test unauthorized access to grants."""
        response = requests.get(f"{wait_for_api}/grants")
        assert response.status_code == 401

    def test_11_grant_expiry_validation(self, wait_for_api, kubeconfig):
        """Test grant expiry validation."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "test-cluster",
                "expiry_hours": 0
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 422

        response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "test-cluster",
                "expiry_hours": 1000
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 422

    def test_12_invalid_role(self, wait_for_api, kubeconfig):
        """Test invalid role validation."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "invalid-role"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 422

    def test_13_missing_kubeconfig(self, wait_for_api):
        """Test behavior when kubeconfig is missing."""
        login_response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]

        response = requests.post(
            f"{wait_for_api}/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view"
            },
            headers={"Authorization": f"Bearer {token}"}
        )

    def test_14_duplicate_user_registration(self, wait_for_api):
        """Test duplicate user registration handling."""
        requests.post(
            f"{wait_for_api}/users",
            json={
                "email": "duplicate@example.com",
                "password": "testpassword123"
            }
        )

        response = requests.post(
            f"{wait_for_api}/users",
            json={
                "email": "duplicate@example.com",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 400
        assert "already registered" in response.json().get("detail", "").lower()

    def test_15_wrong_password_login(self, wait_for_api):
        """Test login with wrong password."""
        requests.post(
            f"{wait_for_api}/users",
            json={
                "email": "wrongpass@example.com",
                "password": "correctpassword"
            }
        )

        response = requests.post(
            f"{wait_for_api}/login",
            json={
                "email": "wrongpass@example.com",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
