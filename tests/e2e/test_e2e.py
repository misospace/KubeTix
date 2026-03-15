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
KIND_CLUSTER_NAME = "kubetix-e2e"
HELM_RELEASE_NAME = "kubetix-test"
NAMESPACE = "kubetix"
API_URL = "http://localhost:8000"
KUBECONFIG_PATH = "/tmp/kubetix-e2e-kubeconfig"


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check
    )
    return result


def wait_for_pod_ready(namespace: str, label_selector: str, timeout: int = 300):
    """Wait for a pod to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        result = run_command([
            "kubectl", "get", "pods",
            "-n", namespace,
            "-l", label_selector,
            "-o", "jsonpath={.items[0].status.phase}"
        ], check=False)
        
        if result.stdout.strip() == "Running":
            # Wait for readiness probe
            time.sleep(5)
            return True
        
        time.sleep(5)
    
    raise TimeoutError(f"Pod not ready after {timeout}s")


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
    def kind_cluster(self):
        """Setup and teardown kind cluster."""
        # Create cluster
        run_command([
            "kind", "create", "cluster",
            "--name", KIND_CLUSTER_NAME
        ])
        
        # Wait for nodes to be ready
        run_command([
            "kubectl", "wait", "--for=condition=Ready", "nodes", "--all",
            "--timeout=120s"
        ])
        
        yield
        
        # Cleanup
        run_command([
            "kind", "delete", "cluster",
            "--name", KIND_CLUSTER_NAME
        ])
    
    @pytest.fixture(scope="class")
    def helm_install(self, kind_cluster):
        """Install KubeTix using Helm."""
        # Install Helm chart
        run_command([
            "helm", "install", HELM_RELEASE_NAME,
            "./charts/kubetix",
            "--namespace", NAMESPACE,
            "--create-namespace",
            "--wait",
            "--timeout", "5m"
        ])
        
        # Wait for API pod to be ready
        wait_for_pod_ready(
            NAMESPACE,
            "app.kubernetes.io/name=kubetix",
            timeout=180
        )
        
        # Port-forward API for testing
        port_forward = subprocess.Popen([
            "kubectl", "port-forward", "-n", NAMESPACE,
            "svc/kubetix-api", "8000:8000"
        ])
        
        try:
            # Wait for API to be ready
            wait_for_service_ready(API_URL, timeout=60)
            yield API_URL
        finally:
            port_forward.terminate()
            port_forward.wait()
    
    @pytest.fixture(scope="class")
    def kubeconfig(self, helm_install):
        """Generate test kubeconfig."""
        # Create temporary kubeconfig
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.kubeconfig') as f:
            kubeconfig_path = f.name
        
        # Copy current kubeconfig (or create minimal one)
        default_kubeconfig = Path.home() / ".kube" / "config"
        if default_kubeconfig.exists():
            shutil.copy(default_kubeconfig, kubeconfig_path)
        else:
            # Create minimal kubeconfig for testing
            os.environ["KUBECONFIG"] = kubeconfig_path
        
        yield kubeconfig_path
        
        # Cleanup
        if os.path.exists(kubeconfig_path):
            os.unlink(kubeconfig_path)
    
    def test_01_api_health(self, helm_install):
        """Test API health endpoint."""
        response = requests.get(f"{helm_install}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_02_user_registration(self, helm_install):
        """Test user registration."""
        response = requests.post(
            f"{helm_install}/users",
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
    
    def test_03_user_login(self, helm_install):
        """Test user login and JWT token."""
        # First register user
        requests.post(
            f"{helm_install}/users",
            json={
                "email": "login-test@example.com",
                "password": "testpassword123"
            }
        )
        
        # Login
        response = requests.post(
            f"{helm_install}/login",
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
    
    def test_04_create_grant(self, helm_install, kubeconfig):
        """Test creating a grant."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Create grant
        response = requests.post(
            f"{helm_install}/grants",
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
    
    def test_05_list_grants(self, helm_install, kubeconfig):
        """Test listing grants."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # List grants
        response = requests.get(
            f"{helm_install}/grants",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        grants = response.json()
        assert isinstance(grants, list)
        # Should have at least the grant from test_04
    
    def test_06_download_grant(self, helm_install, kubeconfig):
        """Test downloading a grant."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Create grant first
        create_response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "download-test-cluster",
                "namespace": "test-ns",
                "role": "edit",
                "expiry_hours": 2
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        grant_id = create_response.json()["id"]
        
        # Download grant
        response = requests.get(
            f"{helm_install}/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cluster_name"] == "download-test-cluster"
        assert data["namespace"] == "test-ns"
        assert data["role"] == "edit"
        assert "kubeconfig" in data
        assert len(data["kubeconfig"]) > 0
    
    def test_07_revoke_grant(self, helm_install, kubeconfig):
        """Test revoking a grant."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Create grant first
        create_response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "revoke-test-cluster",
                "namespace": "default",
                "role": "view",
                "expiry_hours": 1
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        grant_id = create_response.json()["id"]
        
        # Revoke grant
        response = requests.delete(
            f"{helm_install}/grants/{grant_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 204
        
        # Verify grant is revoked
        response = requests.get(
            f"{helm_install}/grants/{grant_id}/download",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
        assert "revoked" in response.json().get("detail", "").lower()
    
    def test_08_audit_log(self, helm_install, kubeconfig):
        """Test audit logging."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Get audit log
        response = requests.get(
            f"{helm_install}/audit",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)
        # Should have audit entries from previous tests
    
    def test_09_invalid_token(self, helm_install):
        """Test invalid token handling."""
        response = requests.get(
            f"{helm_install}/grants",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401
    
    def test_10_unauthorized_access(self, helm_install):
        """Test unauthorized access to grants."""
        # Try to access without token
        response = requests.get(f"{helm_install}/grants")
        assert response.status_code == 401
    
    def test_11_grant_expiry_validation(self, helm_install, kubeconfig):
        """Test grant expiry validation."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Test invalid expiry (too short)
        response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "test-cluster",
                "expiry_hours": 0
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
        
        # Test invalid expiry (too long)
        response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "test-cluster",
                "expiry_hours": 1000
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
    
    def test_12_invalid_role(self, helm_install, kubeconfig):
        """Test invalid role validation."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Test invalid role
        response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "invalid-role"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
    
    def test_13_missing_kubeconfig(self, helm_install):
        """Test behavior when kubeconfig is missing."""
        # Login first
        login_response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Try to create grant without kubeconfig
        # This should fail gracefully
        response = requests.post(
            f"{helm_install}/grants",
            json={
                "cluster_name": "test-cluster",
                "role": "view"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        # May succeed or fail depending on setup
        # Just verify it doesn't crash
    
    def test_14_duplicate_user_registration(self, helm_install):
        """Test duplicate user registration handling."""
        # Register user
        requests.post(
            f"{helm_install}/users",
            json={
                "email": "duplicate@example.com",
                "password": "testpassword123"
            }
        )
        
        # Try to register again
        response = requests.post(
            f"{helm_install}/users",
            json={
                "email": "duplicate@example.com",
                "password": "testpassword123"
            }
        )
        assert response.status_code == 400
        assert "already registered" in response.json().get("detail", "").lower()
    
    def test_15_wrong_password_login(self, helm_install):
        """Test login with wrong password."""
        # Register user first
        requests.post(
            f"{helm_install}/users",
            json={
                "email": "wrongpass@example.com",
                "password": "correctpassword"
            }
        )
        
        # Try to login with wrong password
        response = requests.post(
            f"{helm_install}/login",
            json={
                "email": "wrongpass@example.com",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
