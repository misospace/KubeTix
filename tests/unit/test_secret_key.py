"""
Unit tests for KUBETIX_SECRET_KEY validation.
Verifies that the API refuses to start without KUBETIX_SECRET_KEY set.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestSecretKeyValidation:
    """Tests for KUBETIX_SECRET_KEY environment variable validation."""

    def test_missing_secret_key_raises_value_error(self):
        """Test that missing KUBETIX_SECRET_KEY raises ValueError at import time."""
        api_path = str(Path(__file__).parent.parent.parent.resolve() / "kubetix-api")
        env = os.environ.copy()
        env.pop("KUBETIX_SECRET_KEY", None)
        env["PYTHONPATH"] = api_path
        result = subprocess.run(
            [sys.executable, "-c", "import kubetix_api.auth"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "ValueError" in result.stderr
        assert "KUBETIX_SECRET_KEY" in result.stderr

    def test_valid_secret_key_loads_successfully(self):
        """Test that a valid KUBETIX_SECRET_KEY allows normal import."""
        api_path = str(Path(__file__).parent.parent.parent.resolve() / "kubetix-api")
        env = os.environ.copy()
        env["KUBETIX_SECRET_KEY"] = "test-secret-key-for-testing"
        env["PYTHONPATH"] = api_path
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import kubetix_api.auth; print(kubetix_api.auth.SECRET_KEY)",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "test-secret-key-for-testing" in result.stdout

    def test_secret_key_error_message_includes_generation_hint(self):
        """Test that the error message includes a hint for generating a key."""
        api_path = str(Path(__file__).parent.parent.parent.resolve() / "kubetix-api")
        env = os.environ.copy()
        env.pop("KUBETIX_SECRET_KEY", None)
        env["PYTHONPATH"] = api_path
        result = subprocess.run(
            [sys.executable, "-c", "import kubetix_api.auth"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "secrets.token_urlsafe" in result.stderr
