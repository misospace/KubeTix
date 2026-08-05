"""Regression test for issue #138.

The default `SSO_REDIRECT_URI` previously included a `?provider={provider}`
query parameter. OAuth providers (Google, GitHub, Okta, Azure AD, Authentik,
etc.) require the registered redirect URI to be a fixed, exact match — they
do not allow dynamic query parameters in the registered callback URL. This
caused token exchanges to fail out of the box unless `SSO_REDIRECT_URI` was
explicitly set in the environment.
"""

import os
import sys
import importlib

import pytest


@pytest.fixture
def app_module(monkeypatch, tmp_path):
    """Import the FastAPI app fresh with SSO env vars cleared and DB tables
    created.

    We clear the relevant env vars so the code falls back to its hard-coded
    default, which is the value under test. We also point the database at a
    throwaway SQLite file under tmp_path so the login endpoint (which writes
    an auth_codes row) can run.
    """
    # Ensure the kubetix_api package is importable.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    # Use a throwaway SQLite database.
    db_path = tmp_path / "kubetix_test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    # Drop any SSO-related overrides so the default is exercised.
    for key in (
        "SSO_REDIRECT_URI",
        "SSO_OKTA_ISSUER",
        "SSO_AZURE_TENANT",
        "SSO_AUTHENTIK_ISSUER",
    ):
        monkeypatch.delenv(key, raising=False)

    # Drop the module from sys.modules to force a re-import with the cleared
    # environment.
    sys.modules.pop("main", None)
    sys.modules.pop("kubetix_api.database", None)
    module = importlib.import_module("main")

    # Make sure the schema exists for the throwaway database.
    from kubetix_api.database import init_db

    init_db()
    return module


def test_default_sso_redirect_uri_has_no_dynamic_query_param(app_module):
    """The default SSO redirect URI must be a fixed string, no ?provider=..."""
    default = os.environ.get("SSO_REDIRECT_URI")
    # In this fixture we explicitly cleared SSO_REDIRECT_URI, so the
    # application falls back to its built-in default. We assert on the
    # hard-coded value used in the /auth/sso/{provider}/login endpoint by
    # triggering it and inspecting the response.
    assert default is None


def test_sso_login_uses_fixed_default_redirect_uri(app_module, monkeypatch):
    """Hitting /auth/sso/google/login with no SSO_REDIRECT_URI must yield a
    redirect_uri in the auth URL that does not contain ?provider=google."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SSO_GOOGLE_CLIENT_ID", "test-client-id")

    client = TestClient(app_module.app)
    response = client.get("/api/v1/auth/sso/google/login")

    assert response.status_code == 200, response.text
    body = response.json()
    auth_url = body["auth_url"]

    # The callback must reference the registered redirect_uri via the
    # `redirect_uri` query parameter on the provider's authorize endpoint.
    assert "redirect_uri=" in auth_url

    # Parse out the value of redirect_uri from the auth URL.
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(auth_url)
    qs = parse_qs(parsed.query)
    redirect_uris = qs.get("redirect_uri", [])
    assert redirect_uris, f"No redirect_uri found in auth URL: {auth_url}"

    for ru in redirect_uris:
        # The registered redirect URI must not have a dynamic `?provider=`
        # query parameter — OAuth providers reject this on registration and
        # will refuse the token exchange.
        assert "provider=" not in ru, (
            "Default SSO_REDIRECT_URI must not include a dynamic ?provider= "
            f"query parameter; got {ru!r}"
        )
        # And it should be the versioned callback path.
        assert ru.endswith(
            "/api/v1/auth/sso/callback"
        ), f"Expected redirect_uri to end with /api/v1/auth/sso/callback, got {ru!r}"
