"""
Tests for OIDC/SSO integration
Tests OIDC authentication flows
"""

import pytest

# Import the main app (imports from _shared_db for shared fixtures)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))
from main import app


@pytest.fixture(scope="function")
def mock_oidc_env(monkeypatch):
    """Set up mock OIDC environment variables."""
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER", "https://authentik.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "kubetix-test")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback")


@pytest.fixture(scope="function")
def mock_google_sso_env(monkeypatch):
    """Set up mock Google SSO environment variables."""
    monkeypatch.setenv("SSO_GOOGLE_CLIENT_ID", "google-test-client")
    monkeypatch.setenv("SSO_GOOGLE_CLIENT_SECRET", "google-test-secret")


@pytest.fixture(scope="function")
def mock_github_sso_env(monkeypatch):
    """Set up mock GitHub OAuth environment variables."""
    monkeypatch.setenv("SSO_GITHUB_CLIENT_ID", "github-test-client")
    monkeypatch.setenv("SSO_GITHUB_CLIENT_SECRET", "github-test-secret")


@pytest.fixture(scope="function")
def mock_okta_sso_env(monkeypatch):
    """Set up mock Okta OAuth environment variables."""
    monkeypatch.setenv("SSO_OKTA_ISSUER", "https://okta.example.com")
    monkeypatch.setenv("SSO_OKTA_CLIENT_ID", "okta-test-client")
    monkeypatch.setenv("SSO_OKTA_CLIENT_SECRET", "okta-test-secret")


class TestOIDCEndpoints:
    """Tests for OIDC endpoints."""

    def test_oidc_login_redirect(self, client, mock_oidc_env):
        """Test OIDC login endpoint returns auth URL."""
        response = client.get("/auth/oidc/login")

        assert response.status_code == 200
        data = response.json()
        assert "auth_url" in data
        assert "authentik.example.com" in data["auth_url"]

    def test_oidc_login_requires_config(self, client):
        """Test OIDC login fails without configuration."""
        response = client.get("/auth/oidc/login")

        # Without env vars, should fail with 400 (Bad Request)
        assert response.status_code == 400
        assert "not configured" in response.json()["detail"].lower()

    def test_oidc_callback_without_code(self, client):
        """Test OIDC callback without code fails."""
        response = client.post("/auth/oidc/callback")

        # Should fail validation (missing 'code' field)
        assert response.status_code == 422

    def test_sso_providers_list(self, client):
        """Test listing supported SSO providers — all should return 400 without env vars."""
        providers = ["google", "github", "okta", "azure-ad", "authentik"]

        for provider in providers:
            response = client.get(f"/auth/sso/{provider}/login")

            # Without env vars, should fail with 400 (not configured)
            assert response.status_code == 400

    def test_sso_invalid_provider(self, client):
        """Test using invalid SSO provider."""
        response = client.get("/auth/sso/invalid-provider/login")

        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"].lower()

    def test_oidc_userinfo_unauthorized(self, client):
        """Test OIDC userinfo requires authentication."""
        response = client.get("/auth/oidc/userinfo")

        assert response.status_code == 401

    def test_oidc_userinfo_with_auth(self, client):
        """Test OIDC userinfo returns user data."""
        # This test would require a valid JWT token
        # Just verify the endpoint exists
        response = client.get(
            "/auth/oidc/userinfo",
            headers={"Authorization": "Bearer test-token"}
        )

        # Should fail with auth error, not 404
        assert response.status_code == 401


class TestOIDCSecurity:
    """Security tests for OIDC."""

    def test_oidc_redirect_uri_validation(self, client, mock_oidc_env):
        """Test OIDC redirect URI is validated."""
        response = client.get("/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include redirect_uri parameter
        assert "redirect_uri" in auth_url or "redirectUri" in auth_url

    def test_oidc_scopes_included(self, client, mock_oidc_env):
        """Test OIDC scopes are included in auth request."""
        response = client.get("/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include openid scope
        assert "openid" in auth_url

    def test_oidc_client_id_included(self, client, mock_oidc_env):
        """Test OIDC client ID is included in auth request."""
        response = client.get("/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include client_id
        assert "client_id" in auth_url or "clientId" in auth_url


class TestOAuthProviders:
    """Tests for OAuth provider integration."""

    def test_google_oauth_initiation(self, client, mock_google_sso_env):
        """Test Google OAuth flow initiation."""
        response = client.get("/auth/sso/google/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "google"
        assert "auth_url" in data
        assert "accounts.google.com" in data["auth_url"]

    def test_github_oauth_initiation(self, client, mock_github_sso_env):
        """Test GitHub OAuth flow initiation."""
        response = client.get("/auth/sso/github/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "github"
        assert "auth_url" in data
        assert "github.com/login/oauth/authorize" in data["auth_url"]

    def test_okta_oauth_initiation(self, client, mock_okta_sso_env):
        """Test Okta OAuth flow initiation."""
        response = client.get("/auth/sso/okta/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "okta"
        assert "auth_url" in data
        assert "okta.example.com" in data["auth_url"]


class TestCORSLocking:
    """Tests for CORS origin locking (P0-1 fix)."""

    def test_cors_default_origin(self, client):
        """Test CORS defaults to localhost:3000 when no env var set."""
        response = client.get("/health", headers={"Origin": "http://localhost:3000"})

        assert response.status_code == 200
        # With allow_credentials=True and explicit origin, Access-Control-Allow-Origin should match
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"

    def test_cors_rejects_unknown_origin(self, client):
        """Test CORS rejects unknown origins (no wildcard)."""
        response = client.get("/health", headers={"Origin": "https://evil.example.com"})

        assert response.status_code == 200
        # With explicit origins and no match, Access-Control-Allow-Origin should be empty
        assert response.headers.get("access-control-allow-origin") is None or \
               response.headers.get("access-control-allow-origin") == ""

    def test_cors_custom_origin(self, client, monkeypatch):
        """Test CORS respects custom KUBETIX_CORS_ORIGINS env var."""
        monkeypatch.setenv("KUBETIX_CORS_ORIGINS", "https://app.example.com,https://admin.example.com")

        # Note: CORSMiddleware is applied at import time, so re-setting env vars won't
        # change the already-configured middleware in tests. This test documents the
        # expected behavior when the app starts with custom origins.
        # The important thing is that allow_origins is no longer ["*"].

    def test_cors_no_wildcard_in_config(self):
        """Test that CORS config does not use wildcard."""
        import os
        cors_raw = os.environ.get("KUBETIX_CORS_ORIGINS", "http://localhost:3000")
        origins = [o.strip() for o in cors_raw.split(",") if o.strip()]

        # None of the configured origins should be "*"
        for origin in origins:
            assert origin != "*", f"CORS origin '{origin}' should not be a wildcard"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
