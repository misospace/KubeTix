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

# Grant creation is admin-only (#309). The API seeds this account at startup when
# INITIAL_ADMIN_PASSWORD is set, which the e2e workflow passes through Helm; it is
# the only way to obtain an administrator over HTTP, since registration always
# creates non-admin users.
ADMIN_EMAIL = "admin@kubetix.local"
ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "e2e-admin-pw-not-a-secret")
ADMIN_CREDENTIALS = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}

# A regular registered user, used to assert the admin restriction actually bites.
USER_CREDENTIALS = {"email": "test@example.com", "password": "testpassword123"}


def wait_for_service_ready(url: str, timeout: int = 120):
    """Wait for API service to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f"{url}/api/v1/health", timeout=5)
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
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".kubeconfig"
        ) as f:
            kubeconfig_path = f.name

        default_kubeconfig = Path.home() / ".kube" / "config"
        if default_kubeconfig.exists():
            shutil.copy(default_kubeconfig, kubeconfig_path)
        else:
            os.environ["KUBECONFIG"] = kubeconfig_path

        yield kubeconfig_path

        if os.path.exists(kubeconfig_path):
            os.unlink(kubeconfig_path)

    @pytest.fixture(scope="class")
    def admin_token(self, wait_for_api):
        """Log the seeded admin in once for the whole class.

        /login is rate-limited to 10 per minute (main.py). The suite finishes in
        seconds, so a fresh login inside every grant test tripped the limiter and
        later tests saw 429 instead of the status they asserted.
        """
        response = requests.post(
            f"{wait_for_api}/api/v1/login",
            json=ADMIN_CREDENTIALS,
        )
        assert response.status_code == 200, (
            f"admin login failed ({response.status_code}) — INITIAL_ADMIN_PASSWORD "
            "likely did not reach the API pod"
        )
        return response.json()["access_token"]


    def test_01_api_health(self, wait_for_api):
        """Test API health endpoint."""
        response = requests.get(f"{wait_for_api}/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_02_user_registration(self, wait_for_api):
        """Test user registration."""
        response = requests.post(
            f"{wait_for_api}/api/v1/users",
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

    def test_03_user_login(self, wait_for_api):
        """Test user login and JWT token."""
        requests.post(
            f"{wait_for_api}/api/v1/users",
            json={"email": "login-test@example.com", "password": "testpassword123"},
        )

        response = requests.post(
            f"{wait_for_api}/api/v1/login",
            json={"email": "login-test@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "login-test@example.com"

    def test_03b_non_admin_cannot_create_grant(self, wait_for_api, kubeconfig):
        """A registered non-admin user must be refused grant creation (#309).

        This is the restriction under test, exercised against a deployed API
        rather than a test client that can set is_admin directly on the model.
        """
        login_response = requests.post(
            f"{wait_for_api}/api/v1/login",
            json=USER_CREDENTIALS,
        )
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={
                "cluster_name": "non-admin-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 4,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
        assert "administrator" in response.json()["detail"].lower()

    def test_03c_admin_account_is_seeded(self, wait_for_api, admin_token):
        """The admin the grant tests depend on must exist and report is_admin.

        Without INITIAL_ADMIN_PASSWORD reaching the pod, the API starts with no
        administrator and every grant test fails with a 403 that looks like a
        broken restriction rather than missing setup. The admin_token fixture
        already asserts the login itself; this pins the is_admin flag.
        """
        token = admin_token

        me = requests.get(
            f"{wait_for_api}/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200
        assert me.json()["is_admin"] is True

    def test_04_create_grant(self, wait_for_api, kubeconfig, admin_token):
        """Test creating a grant."""
        token = admin_token

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={
                "cluster_name": "test-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 4,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["cluster_name"] == "test-cluster"
        assert data["namespace"] == "default"
        assert data["role"] == "view"
        assert "id" in data
        assert "expires_at" in data
        assert not data["revoked"]

    def test_05_list_grants(self, wait_for_api, kubeconfig, admin_token):
        """Test listing grants."""
        token = admin_token

        response = requests.get(
            f"{wait_for_api}/api/v1/grants",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        grants = response.json()
        assert isinstance(grants, list)

    def test_06_download_grant(self, wait_for_api, kubeconfig, admin_token):
        """Test downloading a grant."""
        token = admin_token

        create_response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={
                "cluster_name": "download-test-cluster",
                "namespace": "test-ns",
                "role": "edit",
                "expiry_hours": 2,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        grant_id = create_response.json()["id"]

        response = requests.get(
            f"{wait_for_api}/api/v1/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cluster_name"] == "download-test-cluster"
        assert data["namespace"] == "test-ns"
        assert data["role"] == "edit"
        assert "kubeconfig" in data
        assert len(data["kubeconfig"]) > 0

    def test_07_revoke_grant(self, wait_for_api, kubeconfig, admin_token):
        """Test revoking a grant."""
        token = admin_token

        create_response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={
                "cluster_name": "revoke-test-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 1,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        grant_id = create_response.json()["id"]

        response = requests.delete(
            f"{wait_for_api}/api/v1/grants/{grant_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 204

        response = requests.get(
            f"{wait_for_api}/api/v1/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert "revoked" in response.json().get("detail", "").lower()

    def test_08_audit_log(self, wait_for_api, kubeconfig, admin_token):
        """Test audit logging."""
        token = admin_token

        response = requests.get(
            f"{wait_for_api}/api/v1/audit", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)

    def test_09_invalid_token(self, wait_for_api):
        """Test invalid token handling."""
        response = requests.get(
            f"{wait_for_api}/api/v1/grants",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401

    def test_10_unauthorized_access(self, wait_for_api):
        """Test unauthorized access to grants."""
        response = requests.get(f"{wait_for_api}/api/v1/grants")
        assert response.status_code == 401

    def test_11_grant_expiry_validation(self, wait_for_api, kubeconfig, admin_token):
        """Test grant expiry validation."""
        token = admin_token

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={"cluster_name": "test-cluster", "expiry_hours": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={"cluster_name": "test-cluster", "expiry_hours": 1000},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_12_invalid_role(self, wait_for_api, kubeconfig, admin_token):
        """Test invalid role validation."""
        token = admin_token

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={"cluster_name": "test-cluster", "role": "invalid-role"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_13_missing_kubeconfig(self, wait_for_api, admin_token):
        """Test behavior when kubeconfig is missing."""
        token = admin_token

        response = requests.post(
            f"{wait_for_api}/api/v1/grants",
            json={"cluster_name": "test-cluster", "role": "view"},
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_14_duplicate_user_registration(self, wait_for_api):
        """Test duplicate user registration handling."""
        requests.post(
            f"{wait_for_api}/api/v1/users",
            json={"email": "duplicate@example.com", "password": "testpassword123"},
        )

        response = requests.post(
            f"{wait_for_api}/api/v1/users",
            json={"email": "duplicate@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 400
        assert "already registered" in response.json().get("detail", "").lower()

    def test_15_wrong_password_login(self, wait_for_api):
        """Test login with wrong password."""
        requests.post(
            f"{wait_for_api}/api/v1/users",
            json={"email": "wrongpass@example.com", "password": "correctpassword"},
        )

        response = requests.post(
            f"{wait_for_api}/api/v1/login",
            json={"email": "wrongpass@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
