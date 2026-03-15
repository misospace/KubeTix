"""
Pytest fixtures for E2E tests
"""

import pytest
import os
import tempfile


@pytest.fixture(scope="session")
def kind_cluster_name():
    """Return the kind cluster name."""
    return "kubetix-e2e"


@pytest.fixture(scope="session")
def helm_release_name():
    """Return the Helm release name."""
    return "kubetix-test"


@pytest.fixture(scope="session")
def namespace():
    """Return the Kubernetes namespace."""
    return "kubetix"


@pytest.fixture(scope="session")
def api_url():
    """Return the API URL for testing."""
    return "http://localhost:8000"


@pytest.fixture(scope="session", autouse=True)
def setup_environment():
    """Set up test environment."""
    # Ensure we're using the right kubeconfig
    os.environ["KUBECONFIG"] = os.environ.get("KUBECONFIG", "/tmp/kubetix-e2e-kubeconfig")
    yield
    # Cleanup if needed
