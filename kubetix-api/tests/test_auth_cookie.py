"""Regression test for issue #144: Localstorage jwt storage.

The API used to issue bearer tokens that the browser stored in
``sessionStorage`` (and earlier ``localStorage``), which left them readable
to any XSS payload. The fix stores the JWT in an ``httpOnly`` + ``Secure``
+ ``SameSite`` cookie so JavaScript never sees it, and the same cookie is
then accepted by ``get_current_user`` for subsequent requests.
"""

import importlib
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _bootstrap_app(tmp_path, monkeypatch, email, password):
    """Build a fresh FastAPI app with an in-memory DB and a single user."""
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    db_path = tmp_path / f"auth_cookie_{email}.sqlite"
    monkeypatch.setenv("KUBETIX_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KUBETIX_SECRET_KEY", "test-secret-key-for-cookie-suite")
    # Disable SSO/OIDC so the login endpoint is exercisable directly.
    monkeypatch.delenv("SSO_REDIRECT_URI", raising=False)
    monkeypatch.delenv("OIDC_DISCOVERY_URL", raising=False)

    # Drop cached app modules so env vars take effect.
    for name in list(sys.modules):
        if name == "main" or name.startswith("kubetix_api."):
            del sys.modules[name]

    import main as main_module  # type: ignore

    importlib.reload(main_module)

    app = main_module.app

    # Create a user via the API so we exercise the same hashing path.
    with TestClient(app) as client:
        # There is no public signup endpoint, so seed directly.
        from kubetix_api.database import SessionLocal
        from kubetix_api.models import User
        from kubetix_api.auth import get_password_hash

        db = SessionLocal()
        try:
            db.add(
                User(
                    email=email,
                    hashed_password=get_password_hash(password),
                )
            )
            db.commit()
        finally:
            db.close()

    return app, email, password


@pytest.fixture
def app_ctx(tmp_path, monkeypatch):
    # Unique email per test invocation avoids UNIQUE collisions when the
    # in-memory DB is shared via module-level caches.
    email = f"cookie-user-{os.urandom(4).hex()}@example.com"
    password = "hunter2!!"
    app, email, password = _bootstrap_app(tmp_path, monkeypatch, email, password)
    return app, email, password


def test_login_sets_httpOnly_secure_cookie(app_ctx):
    """POST /login must attach the JWT as an httpOnly + Secure cookie."""
    app, email, password = app_ctx

    with TestClient(app) as client:
        resp = client.post("/login", json={"email": email, "password": password})

    assert resp.status_code == 200, resp.text
    set_cookie = resp.headers.get("set-cookie", "")
    assert "kubetix_session=" in set_cookie, set_cookie
    assert "HttpOnly" in set_cookie, set_cookie
    assert "Secure" in set_cookie, set_cookie
    assert "samesite=lax" in set_cookie.lower(), set_cookie


def test_cookie_authenticates_protected_endpoints(app_ctx):
    """The cookie returned by /login must be accepted by /users/me."""
    app, email, password = app_ctx

    with TestClient(app) as client:
        login = client.post("/login", json={"email": email, "password": password})
        assert login.status_code == 200

        # The Set-Cookie header carries HttpOnly + Secure, so the browser
        # would normally gate it behind HTTPS. Extract the cookie value
        # directly here so the test does not depend on TLS plumbing.
        set_cookie = login.headers.get("set-cookie", "")
        # Parse the kubetix_session=<value> token out of the header.
        cookie_value = None
        for piece in set_cookie.split(";"):
            piece = piece.strip()
            if piece.startswith("kubetix_session="):
                cookie_value = piece.split("=", 1)[1]
                break
        assert cookie_value, f"login did not return kubetix_session: {set_cookie!r}"

        me = client.get("/users/me", cookies={"kubetix_session": cookie_value})
        assert me.status_code == 200, me.text
        assert me.json()["email"] == email


def test_logout_clears_auth_cookie(app_ctx):
    """/auth/logout must delete the kubetix_session cookie."""
    app, email, password = app_ctx

    with TestClient(app) as client:
        login = client.post("/login", json={"email": email, "password": password})
        assert login.status_code == 200

        token = login.json()["access_token"]

        # Logout blacklists the token; both the bearer header and the
        # httpOnly cookie should be enough to authenticate the request.
        logout = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert logout.status_code in (204, 200), logout.text
    set_cookie = logout.headers.get("set-cookie", "")
    assert "kubetix_session=" in set_cookie, set_cookie
    # Either expired or empty value — both signal removal.
    assert ("Max-Age=0" in set_cookie) or (
        "kubetix_session=;" in set_cookie
    ), set_cookie
