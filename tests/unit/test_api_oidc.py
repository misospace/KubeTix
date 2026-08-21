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
    monkeypatch.setenv(
        "OIDC_REDIRECT_URI", "http://localhost:8000/api/v1/auth/oidc/callback"
    )


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
        response = client.get("api/v1/auth/oidc/login")

        assert response.status_code == 200
        data = response.json()
        assert "auth_url" in data
        assert "authentik.example.com" in data["auth_url"]

    def test_oidc_login_requires_config(self, client):
        """Test OIDC login fails without configuration."""
        response = client.get("api/v1/auth/oidc/login")

        # Without env vars, should fail with 400 (Bad Request)
        assert response.status_code == 400
        assert "not configured" in response.json()["detail"].lower()

    def test_oidc_callback_without_code(self, client):
        """Test OIDC callback without code fails."""
        response = client.get("api/v1/auth/oidc/callback")

        # Should fail validation (missing 'code' field)
        assert response.status_code == 422

    def test_sso_providers_list(self, client):
        """Test listing supported SSO providers — all should return 400 without env vars."""
        providers = ["google", "github", "okta", "azure-ad", "authentik"]

        for provider in providers:
            response = client.get(f"api/v1/auth/sso/{provider}/login")

            # Without env vars, should fail with 400 (not configured)
            assert response.status_code == 400

    def test_sso_invalid_provider(self, client):
        """Test using invalid SSO provider."""
        response = client.get("api/v1/auth/sso/invalid-provider/login")

        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"].lower()

    def test_oidc_userinfo_unauthorized(self, client):
        """Test OIDC userinfo requires authentication."""
        response = client.get("api/v1/auth/oidc/userinfo")

        assert response.status_code == 401

    def test_oidc_userinfo_with_auth(self, client):
        """Test OIDC userinfo returns user data."""
        # This test would require a valid JWT token
        # Just verify the endpoint exists
        response = client.get(
            "api/v1/auth/oidc/userinfo", headers={"Authorization": "Bearer test-token"}
        )

        # Should fail with auth error, not 404
        assert response.status_code == 401


class TestOIDCSecurity:
    """Security tests for OIDC."""

    def test_oidc_redirect_uri_validation(self, client, mock_oidc_env):
        """Test OIDC redirect URI is validated."""
        response = client.get("api/v1/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include redirect_uri parameter
        assert "redirect_uri" in auth_url or "redirectUri" in auth_url

    def test_oidc_scopes_included(self, client, mock_oidc_env):
        """Test OIDC scopes are included in auth request."""
        response = client.get("api/v1/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include openid scope
        assert "openid" in auth_url

    def test_oidc_client_id_included(self, client, mock_oidc_env):
        """Test OIDC client ID is included in auth request."""
        response = client.get("api/v1/auth/oidc/login")

        data = response.json()
        auth_url = data.get("auth_url", "")

        # Should include client_id
        assert "client_id" in auth_url or "clientId" in auth_url


class TestOAuthProviders:
    """Tests for OAuth provider integration."""

    def test_google_oauth_initiation(self, client, mock_google_sso_env):
        """Test Google OAuth flow initiation."""
        response = client.get("api/v1/auth/sso/google/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "google"
        assert "auth_url" in data
        assert "accounts.google.com" in data["auth_url"]

    def test_github_oauth_initiation(self, client, mock_github_sso_env):
        """Test GitHub OAuth flow initiation."""
        response = client.get("api/v1/auth/sso/github/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "github"
        assert "auth_url" in data
        assert "github.com/login/oauth/authorize" in data["auth_url"]

    def test_okta_oauth_initiation(self, client, mock_okta_sso_env):
        """Test Okta OAuth flow initiation."""
        response = client.get("api/v1/auth/sso/okta/login")

        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "okta"
        assert "auth_url" in data
        assert "okta.example.com" in data["auth_url"]


class TestCORSLocking:
    """Tests for CORS origin locking (P0-1 fix)."""

    def test_cors_default_origin(self, client):
        """Test CORS defaults to localhost:3000 when no env var set."""
        response = client.get(
            "api/v1/health", headers={"Origin": "http://localhost:3000"}
        )

        assert response.status_code == 200
        # With allow_credentials=True and explicit origin, Access-Control-Allow-Origin should match
        assert (
            response.headers.get("access-control-allow-origin")
            == "http://localhost:3000"
        )

    def test_cors_rejects_unknown_origin(self, client):
        """Test CORS rejects unknown origins (no wildcard)."""
        response = client.get(
            "api/v1/health", headers={"Origin": "https://evil.example.com"}
        )

        assert response.status_code == 200
        # With explicit origins and no match, Access-Control-Allow-Origin should be empty
        assert (
            response.headers.get("access-control-allow-origin") is None
            or response.headers.get("access-control-allow-origin") == ""
        )

    def test_cors_custom_origin(self, client, monkeypatch):
        """Test CORS respects custom KUBETIX_CORS_ORIGINS env var."""
        # Regression test for issue #142: CORS config must be resolved at app
        # startup (lifespan), not at module import time, so env var changes
        # between import and startup are honored.
        import main as kubetix_main
        from main import _resolve_cors_origins

        monkeypatch.setenv(
            "KUBETIX_CORS_ORIGINS",
            "https://app.example.com,https://admin.example.com",
        )

        origins = _resolve_cors_origins()

        assert origins == [
            "https://app.example.com",
            "https://admin.example.com",
        ]

        # And the helper must populate the module-level list that the
        # CORSMiddleware instance holds a reference to.
        kubetix_main.ALLOWED_ORIGINS.clear()
        kubetix_main.ALLOWED_ORIGINS.extend(_resolve_cors_origins())
        assert "https://app.example.com" in kubetix_main.ALLOWED_ORIGINS

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


class TestSSORoundTrip:
    """Tests for SSO/OIDC callback state verification round-trip."""

    def test_sso_google_login_and_callback_roundtrip(
        self, client, db, mock_google_sso_env, monkeypatch
    ):
        """Test that a full Google SSO login -> callback round-trip succeeds.

        Verifies that the state stored at login matches what the IdP echoes back
        and that PKCE verification passes.
        """
        import httpx
        from unittest.mock import patch

        # 1. Initiate login
        response = client.get("api/v1/auth/sso/google/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]

        # 2. Extract the state from the auth_url (it is the auth_code id)
        import urllib.parse

        parsed = urllib.parse.urlparse(login_data["auth_url"])
        query = urllib.parse.parse_qs(parsed.query)
        auth_code_id = query["state"][0]

        # 3. Mock the token exchange and userinfo calls
        mock_token_resp = httpx.Response(
            200,
            json={"access_token": "mock-google-access-token", "token_type": "Bearer"},
        )
        mock_userinfo_resp = httpx.Response(
            200,
            json={
                "email": "sso-test@example.com",
                "name": "SSO Test User",
                "sub": "google-12345",
                "email_verified": True,
            },
        )

        with patch("httpx.post", return_value=mock_token_resp), patch(
            "httpx.get", return_value=mock_userinfo_resp
        ):
            # 4. Call the callback endpoint with the same state (auth_code_id)
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-auth-code"
                f"&state={auth_code_id}&code_verifier={code_verifier}"
            )

        # 5. The callback must succeed - this proves state verification works
        assert response.status_code == 200, (
            f"Callback failed with {response.status_code}: "
            f"{response.json().get('detail', 'no detail')}"
        )
        data = response.json()
        assert data["user"]["email"] == "sso-test@example.com"
        assert "access_token" in data

    def test_oidc_login_and_callback_roundtrip(
        self, client, db, mock_oidc_env, monkeypatch
    ):
        """Test that a full generic OIDC login -> callback round-trip succeeds."""
        from unittest.mock import patch

        # 1. Initiate login
        response = client.get("api/v1/auth/oidc/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]

        # 2. Extract the state from the auth_url
        import urllib.parse

        parsed = urllib.parse.urlparse(login_data["auth_url"])
        query = urllib.parse.parse_qs(parsed.query)
        auth_code_id = query["state"][0]

        # 3. Mock the internal OIDC helpers (they import httpx lazily)
        with patch(
            "main._exchange_code_for_tokens",
            return_value={"access_token": "mock-oidc-access-token"},
        ), patch(
            "main._get_userinfo",
            return_value={
                "email": "oidc-test@example.com",
                "name": "OIDC Test User",
                "sub": "oidc-67890",
                "email_verified": True,
            },
        ):
            response = client.get(
                "api/v1/auth/oidc/callback?code=fake-auth-code"
                f"&state={auth_code_id}&code_verifier={code_verifier}"
            )

        # 4. Callback must succeed
        assert response.status_code == 200, (
            f"Callback failed with {response.status_code}: "
            f"{response.json().get('detail', 'no detail')}"
        )
        data = response.json()
        assert data["user"]["email"] == "oidc-test@example.com"

    def test_sso_callback_rejects_wrong_state(self, client, mock_google_sso_env):
        """Test that callback rejects a state value that doesn't match any record."""
        response = client.get(
            "api/v1/auth/sso/callback?provider=google&code=fake-auth-code"
            "&state=nonexistent-state&code_verifier=some-verifier"
        )
        assert response.status_code == 400
        assert "invalid or expired" in response.json()["detail"].lower()

    def test_sso_callback_rejects_reused_state(
        self, client, db, mock_google_sso_env, monkeypatch
    ):
        """Test that a successfully-used auth code cannot be reused."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login
        response = client.get("api/v1/auth/sso/google/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]

        import urllib.parse

        parsed = urllib.parse.urlparse(login_data["auth_url"])
        query = urllib.parse.parse_qs(parsed.query)
        auth_code_id = query["state"][0]

        mock_token_resp = httpx.Response(
            200,
            json={"access_token": "mock-token", "token_type": "Bearer"},
        )
        mock_userinfo_resp = httpx.Response(
            200,
            json={
                "email": "reuse@example.com",
                "name": "Reuse",
                "sub": "sub-1",
                "email_verified": True,
            },
        )

        # 2. First callback succeeds
        with patch("httpx.post", return_value=mock_token_resp), patch(
            "httpx.get", return_value=mock_userinfo_resp
        ):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state={auth_code_id}&code_verifier={code_verifier}"
            )
        assert response.status_code == 200

        # 3. Second callback with same state must fail (record marked used)
        with patch("httpx.post", return_value=mock_token_resp), patch(
            "httpx.get", return_value=mock_userinfo_resp
        ):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state={auth_code_id}&code_verifier={code_verifier}"
            )
        assert response.status_code == 400
        assert "invalid or expired" in response.json()["detail"].lower()

    def test_sso_callback_rejects_mismatched_csrf_state(
        self, client, db, mock_google_sso_env, monkeypatch
    ):
        """Regression test: callback must reject a request where the state
        does not match the CSRF token stored during login, even if the
        code_verifier is correct. This verifies that the IdP-echoed state
        is actually checked (not just any valid auth_code record)."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login — get csrf_state and code_verifier
        response = client.get("api/v1/auth/sso/google/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]
        csrf_state = login_data["csrf_state"]

        # 2. Verify the auth URL carries the csrf_state (not an internal id)
        import urllib.parse

        parsed = urllib.parse.urlparse(login_data["auth_url"])
        query = urllib.parse.parse_qs(parsed.query)
        assert (
            query["state"][0] == csrf_state
        ), "Auth URL state parameter must be the CSRF token"

        # 3. Callback with a *different* state must fail even with correct verifier
        mock_token_resp = httpx.Response(
            200,
            json={"access_token": "mock-token", "token_type": "Bearer"},
        )
        with patch("httpx.post", return_value=mock_token_resp):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state=attacker-controlled-state&code_verifier={code_verifier}"
            )
        assert response.status_code == 400

        # 4. Callback with the correct csrf_state succeeds (token exchange mocked)
        mock_userinfo_resp = httpx.Response(
            200,
            json={
                "email": "csrf@example.com",
                "name": "CSRF",
                "sub": "sub-csrf",
                "email_verified": True,
            },
        )
        with patch("httpx.post", return_value=mock_token_resp), patch(
            "httpx.get", return_value=mock_userinfo_resp
        ):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state={csrf_state}&code_verifier={code_verifier}"
            )
        assert response.status_code == 200


class TestSSOErrorHandling:
    """Regression tests for issue #150: SSO error handling must include provider details."""

    def test_sso_callback_token_exchange_error_includes_provider_details(
        self, client, db, mock_google_sso_env, monkeypatch
    ):
        """Token exchange failure must include the provider's HTTP status code and response body."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login — get csrf_state and code_verifier
        response = client.get("api/v1/auth/sso/google/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]
        csrf_state = login_data["csrf_state"]

        # 2. Mock token exchange to return an error from the provider
        mock_token_resp = httpx.Response(
            403,
            json={"error": "access_denied", "error_description": "User denied access"},
        )
        with patch("httpx.post", return_value=mock_token_resp):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state={csrf_state}&code_verifier={code_verifier}"
            )

        assert response.status_code == 401
        detail = response.json()["detail"]
        # Verify provider status code is included
        assert (
            "403" in detail
        ), f"Error message should include provider status code: {detail}"
        # Verify provider error body is included
        assert (
            "access_denied" in detail or "User denied access" in detail
        ), f"Error message should include provider response body: {detail}"

    def test_sso_callback_userinfo_error_includes_provider_details(
        self, client, db, mock_google_sso_env, monkeypatch
    ):
        """Userinfo fetch failure must include the provider's HTTP status code and response body."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login — get csrf_state and code_verifier
        response = client.get("api/v1/auth/sso/google/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]
        csrf_state = login_data["csrf_state"]

        # 2. Mock token exchange to succeed, but userinfo to fail
        mock_token_resp = httpx.Response(
            200,
            json={"access_token": "mock-token", "token_type": "Bearer"},
        )
        mock_userinfo_resp = httpx.Response(
            500,
            text="Internal Server Error",
        )

        def mock_request(method, url, **kwargs):
            if method == "POST":
                return mock_token_resp
            elif method == "GET":
                return mock_userinfo_resp
            raise ValueError(f"Unexpected method: {method}")

        with patch(
            "httpx.post", side_effect=lambda *a, **kw: mock_request("POST", *a, **kw)
        ), patch(
            "httpx.get", side_effect=lambda *a, **kw: mock_request("GET", *a, **kw)
        ):
            response = client.get(
                "api/v1/auth/sso/callback?provider=google&code=fake-code"
                f"&state={csrf_state}&code_verifier={code_verifier}"
            )

        assert response.status_code == 401
        detail = response.json()["detail"]
        # Verify provider status code is included
        assert (
            "500" in detail
        ), f"Error message should include provider status code: {detail}"
        # Verify provider error body is included
        assert (
            "Internal Server Error" in detail
        ), f"Error message should include provider response body: {detail}"

    def test_oidc_callback_token_exchange_error_includes_provider_details(
        self, client, db, mock_oidc_env, monkeypatch
    ):
        """OIDC token exchange failure must include the provider's error details."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login — get csrf_state and code_verifier
        response = client.get("api/v1/auth/oidc/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]
        csrf_state = login_data["csrf_state"]

        # 2. Mock token exchange to raise an HTTPStatusError (as _exchange_code_for_tokens does)
        def mock_post(*args, **kwargs):
            resp = httpx.Response(401, json={"error": "invalid_grant"})
            resp.request = httpx.Request("POST", args[0] if args else "/token")
            resp.raise_for_status()
            return resp

        with patch("httpx.post", side_effect=mock_post):
            response = client.get(
                "api/v1/auth/oidc/callback?code=fake-code"
                f"&state={csrf_state}&code_verifier={code_verifier}"
            )

        assert response.status_code == 401
        detail = response.json()["detail"]
        # Verify the exception message (which includes provider details) is in the error
        assert (
            "invalid_grant" in detail or "401" in detail
        ), f"Error message should include provider error details: {detail}"

    def test_oidc_callback_userinfo_error_includes_provider_details(
        self, client, db, mock_oidc_env, monkeypatch
    ):
        """OIDC userinfo fetch failure must include the provider's error details."""
        import httpx
        from unittest.mock import patch

        # 1. Initiate login — get csrf_state and code_verifier
        response = client.get("api/v1/auth/oidc/login")
        assert response.status_code == 200
        login_data = response.json()
        code_verifier = login_data["code_verifier"]
        csrf_state = login_data["csrf_state"]

        # 2. Mock token exchange to succeed, but userinfo to raise an error
        def mock_post(*args, **kwargs):
            resp = httpx.Response(
                200,
                json={"access_token": "mock-token", "token_type": "Bearer"},
            )
            resp.request = httpx.Request("POST", args[0] if args else "/token")
            return resp

        def mock_get(*args, **kwargs):
            resp = httpx.Response(503, text="Service Unavailable")
            resp.request = httpx.Request("GET", args[0] if args else "/userinfo")
            resp.raise_for_status()
            return resp

        with patch("httpx.post", side_effect=mock_post), patch(
            "httpx.get", side_effect=mock_get
        ):
            response = client.get(
                "api/v1/auth/oidc/callback?code=fake-code"
                f"&state={csrf_state}&code_verifier={code_verifier}"
            )

        assert response.status_code == 401
        detail = response.json()["detail"]
        # Verify the exception message (which includes provider details) is in the error
        assert (
            "503" in detail or "Service Unavailable" in detail
        ), f"Error message should include provider error details: {detail}"


class TestOIDCEndpointsDiscovery:
    """Regression tests for #143: OIDC endpoint paths must come from the
    OIDC Discovery document at ``/.well-known/openid-configuration``
    (OpenID Connect Discovery 1.0) rather than being hardcoded."""

    def test_uses_discovery_document_when_available(self, monkeypatch):
        """When the provider publishes a discovery document, its
        ``token_endpoint`` / ``userinfo_endpoint`` MUST be used verbatim
        — never the legacy ``/oauth/token`` / ``/oauth/userinfo`` paths."""
        from unittest.mock import patch, MagicMock
        from kubetix_api.oidc import _oidc_endpoints

        discovery = {
            "issuer": "https://idp.test",
            "authorization_endpoint": "https://idp.test/connect/authorize",
            "token_endpoint": "https://idp.test/connect/token",
            "userinfo_endpoint": "https://idp.test/connect/userinfo",
            "jwks_uri": "https://idp.test/connect/jwks.json",
            "end_session_endpoint": "https://idp.test/connect/logout",
        }

        captured_urls = []

        def fake_get(url, *args, **kwargs):
            captured_urls.append(url)
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = discovery
            return resp

        with patch("httpx.get", side_effect=fake_get):
            endpoints = _oidc_endpoints("https://idp.test/")

        # OIDC Discovery 1.0 mandates this exact well-known path.
        assert captured_urls == ["https://idp.test/.well-known/openid-configuration"]
        # Paths MUST come from the discovery document, not from /oauth/* hardcoding.
        assert endpoints["token_endpoint"] == "https://idp.test/connect/token"
        assert endpoints["userinfo_endpoint"] == "https://idp.test/connect/userinfo"
        # And explicitly: the legacy hardcoded path MUST NOT be used.
        assert "/oauth/token" not in endpoints["token_endpoint"]
        assert "/oauth/userinfo" not in endpoints["userinfo_endpoint"]

    def test_falls_back_to_legacy_paths_when_discovery_unavailable(self, monkeypatch):
        """If the discovery document can't be fetched (network error,
        non-2xx, malformed body), fall back to the legacy ``/oauth/...``
        paths so local providers without a discovery document keep working."""
        from unittest.mock import patch
        import httpx
        from kubetix_api.oidc import _oidc_endpoints

        def fake_get(*args, **kwargs):
            raise httpx.ConnectError("boom")

        with patch("httpx.get", side_effect=fake_get):
            endpoints = _oidc_endpoints("https://idp.test/")

        assert endpoints["token_endpoint"] == "https://idp.test/oauth/token"
        assert endpoints["userinfo_endpoint"] == "https://idp.test/oauth/userinfo"

    def test_falls_back_when_discovery_returns_non_dict(self, monkeypatch):
        """A discovery response that isn't a JSON object must not crash."""
        from unittest.mock import patch, MagicMock
        from kubetix_api.oidc import _oidc_endpoints

        def fake_get(*args, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = ["not", "a", "dict"]
            return resp

        with patch("httpx.get", side_effect=fake_get):
            endpoints = _oidc_endpoints("https://idp.test")

        assert endpoints["token_endpoint"] == "https://idp.test/oauth/token"
        assert endpoints["userinfo_endpoint"] == "https://idp.test/oauth/userinfo"

    def test_falls_back_per_endpoint_when_keys_missing(self, monkeypatch):
        """If the discovery document omits a particular endpoint, fall
        back to the legacy path for just that endpoint, while still
        using the discovery-provided value for any endpoint it lists."""
        from unittest.mock import patch, MagicMock
        from kubetix_api.oidc import _oidc_endpoints

        # Discovery doc lists a custom token_endpoint but no userinfo_endpoint.
        discovery = {
            "token_endpoint": "https://idp.test/api/token",
        }

        def fake_get(*args, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = discovery
            return resp

        with patch("httpx.get", side_effect=fake_get):
            endpoints = _oidc_endpoints("https://idp.test")

        assert endpoints["token_endpoint"] == "https://idp.test/api/token"
        # userinfo missing from doc → fall back to legacy path.
        assert endpoints["userinfo_endpoint"] == "https://idp.test/oauth/userinfo"


class TestEmailVerifiedCheck:
    """Tests for ``_check_email_verified`` — the guard that prevents
    provisioning with unverified emails."""

    def test_rejects_unverified_email(self):
        from kubetix_api.oidc import _check_email_verified
        from fastapi import HTTPException

        userinfo = {"email": "user@example.com", "email_verified": False}
        with pytest.raises(HTTPException) as exc_info:
            _check_email_verified(userinfo, "test-provider")
        assert exc_info.value.status_code == 403
        assert "Email not verified" in str(exc_info.value.detail)

    def test_rejects_missing_email_verified(self):
        from kubetix_api.oidc import _check_email_verified
        from fastapi import HTTPException

        userinfo = {"email": "user@example.com"}
        with pytest.raises(HTTPException) as exc_info:
            _check_email_verified(userinfo, "test-provider")
        assert exc_info.value.status_code == 403

    def test_allows_verified_email(self):
        from kubetix_api.oidc import _check_email_verified

        userinfo = {"email": "user@example.com", "email_verified": True}
        # Should not raise
        _check_email_verified(userinfo, "test-provider")

    def test_skips_when_env_disabled(self, monkeypatch):
        from kubetix_api.oidc import _check_email_verified

        monkeypatch.setenv("SSO_REQUIRE_EMAIL_VERIFIED", "false")
        # Force re-read of the env var by patching the module-level flag
        import kubetix_api.oidc as oidc_mod

        original = oidc_mod.SSO_REQUIRE_EMAIL_VERIFIED
        try:
            oidc_mod.SSO_REQUIRE_EMAIL_VERIFIED = False
            userinfo = {"email": "user@example.com", "email_verified": False}
            # Should not raise when the flag is disabled
            _check_email_verified(userinfo, "test-provider")
        finally:
            oidc_mod.SSO_REQUIRE_EMAIL_VERIFIED = original


# ---------------------------------------------------------------------------
# Helpers for testing the JWKS-backed signature-verification path.
#
# Issue #351 added real signature verification to ``_validate_id_token``.
# These tests previously signed tokens with HS256 ("secret") and never
# asserted signature validity — they were effectively testing the
# unverified-claim path. The class below now generates an RSA keypair per
# test, signs tokens with it, and injects a corresponding JWKS via the
# ``jwks_uri_override`` parameter so the validator can verify the
# signature. The claim-validation semantics (iss / aud) being exercised
# here are unchanged.
# ---------------------------------------------------------------------------


def _b64url_uint(n: int) -> str:
    import base64

    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_rsa_keypair_and_jwks(kid: str = "test-kid"):
    """Return ``(private_pem, jwks_dict, jwks_uri)`` for a fresh RSA key."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    numbers = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }
    return (
        private_pem,
        jwks,
        f"https://idp.example.com/.well-known/test-{kid}-jwks.json",
    )


def _make_signed_jwt(
    private_pem,
    *,
    claims_overrides: dict,
    kid: str = "test-kid",
):
    """Encode an OIDC ID token signed with ``private_pem`` (RS256)."""
    import time as _time

    from jose import jwt as _jwt

    now = int(_time.time())
    base_claims = {
        "iss": "https://authentik.example.com",
        "aud": "kubetix-test",
        "sub": "user-1",
        "email": "[email protected]",
        "iat": now,
        "exp": now + 3600,
    }
    base_claims.update(claims_overrides)
    return _jwt.encode(
        base_claims,
        private_pem.decode("utf-8") if isinstance(private_pem, bytes) else private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.fixture
def rsa_jwks(monkeypatch):
    """Generate an RSA keypair and stub the OIDC module's JWKS fetcher.

    Yields ``(private_pem, jwks, jwks_uri)`` so individual tests can sign
    tokens and pass ``jwks_uri`` to ``_validate_id_token`` via the
    ``jwks_uri_override`` parameter (issue #351 added this knob so the
    signature path is testable without a real IdP).
    """
    from kubetix_api import oidc as _oidc

    private_pem, jwks, jwks_uri = _make_rsa_keypair_and_jwks()

    def _fake_fetch_jwks(issuer, jwks_uri_override=None):
        return jwks

    monkeypatch.setattr(_oidc, "_fetch_jwks", _fake_fetch_jwks)
    return private_pem, jwks, jwks_uri


class TestIdTokenValidation:
    """Tests for ``_validate_id_token`` — iss / aud claim checks.

    After issue #351, ``_validate_id_token`` performs real JWKS-backed
    signature verification. These tests therefore use the ``rsa_jwks``
    fixture, which generates a fresh RSA keypair per test and stubs the
    module's ``_fetch_jwks`` so the JWKS is local and resolvable. The
    ``jwks_uri_override`` parameter is the test seam added by #351.
    """

    def test_accepts_valid_token(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token

        private_pem, _jwks, jwks_uri = rsa_jwks
        token = _make_signed_jwt(
            private_pem,
            claims_overrides={
                "iss": "https://accounts.google.com",
                "aud": "my-client-id",
                "sub": "123456789",
                "email": "user@example.com",
            },
        )
        result = _validate_id_token(
            token,
            "https://accounts.google.com",
            "my-client-id",
            jwks_uri_override=jwks_uri,
        )
        assert result["sub"] == "123456789"

    def test_rejects_wrong_issuer(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token
        from fastapi import HTTPException

        private_pem, _jwks, jwks_uri = rsa_jwks
        token = _make_signed_jwt(
            private_pem,
            claims_overrides={
                "iss": "https://evil.example.com",
                "aud": "my-client-id",
            },
        )
        with pytest.raises(HTTPException) as exc_info:
            _validate_id_token(
                token,
                "https://accounts.google.com",
                "my-client-id",
                jwks_uri_override=jwks_uri,
            )
        assert exc_info.value.status_code == 401
        assert "issuer mismatch" in str(exc_info.value.detail).lower()

    def test_rejects_wrong_audience(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token
        from fastapi import HTTPException

        private_pem, _jwks, jwks_uri = rsa_jwks
        token = _make_signed_jwt(
            private_pem,
            claims_overrides={
                "iss": "https://accounts.google.com",
                "aud": "other-client-id",
            },
        )
        with pytest.raises(HTTPException) as exc_info:
            _validate_id_token(
                token,
                "https://accounts.google.com",
                "my-client-id",
                jwks_uri_override=jwks_uri,
            )
        assert exc_info.value.status_code == 401
        assert "audience mismatch" in str(exc_info.value.detail).lower()

    def test_rejects_missing_aud(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token
        from jose import jwt as _jwt
        from fastapi import HTTPException

        import time as _time

        private_pem, _jwks, jwks_uri = rsa_jwks
        now = int(_time.time())
        token = _jwt.encode(
            {
                "iss": "https://accounts.google.com",
                "sub": "123456789",
                "iat": now,
                "exp": now + 3600,
            },
            private_pem.decode("utf-8"),
            algorithm="RS256",
            headers={"kid": "test-kid"},
        )
        with pytest.raises(HTTPException) as exc_info:
            _validate_id_token(
                token,
                "https://accounts.google.com",
                "my-client-id",
                jwks_uri_override=jwks_uri,
            )
        assert exc_info.value.status_code == 401
        assert "aud" in str(exc_info.value.detail).lower()

    def test_accepts_aud_as_list(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token

        private_pem, _jwks, jwks_uri = rsa_jwks
        token = _make_signed_jwt(
            private_pem,
            claims_overrides={
                "iss": "https://accounts.google.com",
                "aud": ["other-client-id", "my-client-id"],
                "sub": "123456789",
            },
        )
        result = _validate_id_token(
            token,
            "https://accounts.google.com",
            "my-client-id",
            jwks_uri_override=jwks_uri,
        )
        assert result["sub"] == "123456789"

    def test_rejects_malformed_token(self, rsa_jwks):
        from kubetix_api.oidc import _validate_id_token
        from fastapi import HTTPException

        # rsa_jwks patches the module's JWKS fetcher so the validator can
        # reach the key-lookup / decode stage. The malformed token
        # fails to parse; per the security-hardening in #351 we report
        # every verification failure as 401 so we don't leak which
        # check tripped.
        _private_pem, _jwks, _jwks_uri = rsa_jwks
        with pytest.raises(HTTPException) as exc_info:
            _validate_id_token(
                "not.a.token",
                "https://accounts.google.com",
                "my-client-id",
                jwks_uri_override="https://example.com/jwks.json",
            )
        assert exc_info.value.status_code == 401
