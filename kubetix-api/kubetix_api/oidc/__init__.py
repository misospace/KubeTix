"""OIDC / SSO helpers — token exchange, PKCE, user provisioning."""

import hashlib
import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, Depends, status

from kubetix_api.database import get_db, SessionLocal
from kubetix_api.auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from kubetix_api.models import User, provision_user

# ---------------------------------------------------------------------------
# OIDC endpoint resolution
# ---------------------------------------------------------------------------

_OIDC_DISCOVERY_TIMEOUT_SECONDS = 5.0


def _fetch_oidc_discovery(issuer: str) -> dict | None:
    """Fetch the OpenID Connect Discovery document for ``issuer``.

    Per OpenID Connect Discovery 1.0 the document lives at
    ``{issuer}/.well-known/openid-configuration`` and exposes the canonical
    ``token_endpoint`` / ``userinfo_endpoint`` (plus jwks_uri, etc.).

    Returns the parsed JSON document, or ``None`` if discovery is unavailable
    (network error, non-2xx response, malformed body, etc.).
    """
    import httpx

    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = httpx.get(discovery_url, timeout=_OIDC_DISCOVERY_TIMEOUT_SECONDS)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _oidc_endpoints(issuer: str) -> dict:
    """Return OIDC endpoint URLs for ``issuer``.

    Resolves endpoints via the OIDC Discovery document at
    ``{issuer}/.well-known/openid-configuration`` (OpenID Connect Discovery 1.0)
    so we honor the provider's published paths instead of assuming the legacy
    ``/oauth/token`` and ``/oauth/userinfo`` layout.

    Falls back to those legacy ``/oauth/...`` paths when discovery is
    unavailable so local providers that don't publish a discovery document
    keep working.
    """
    base = issuer.rstrip("/")
    document = _fetch_oidc_discovery(issuer)
    if document:
        return {
            "token_endpoint": document.get("token_endpoint", f"{base}/oauth/token"),
            "userinfo_endpoint": document.get(
                "userinfo_endpoint", f"{base}/oauth/userinfo"
            ),
        }
    return {
        "token_endpoint": f"{base}/oauth/token",
        "userinfo_endpoint": f"{base}/oauth/userinfo",
    }


def _exchange_code_for_tokens(
    issuer: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict:
    """Exchange an authorization code for access + ID tokens."""
    import httpx

    endpoints = _oidc_endpoints(issuer)
    token_url = endpoints["token_endpoint"]

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    resp = httpx.post(token_url, data=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _get_userinfo(issuer: str, access_token: str) -> dict:
    """Fetch user info from the OIDC provider using the access token."""
    import httpx

    endpoints = _oidc_endpoints(issuer)
    userinfo_url = endpoints["userinfo_endpoint"]

    headers = {"Authorization": f"Bearer {access_token}"}
    resp = httpx.get(userinfo_url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# PKCE helpers (RFC 7636)
# ---------------------------------------------------------------------------


def _generate_pkce_params() -> tuple[str, str]:
    """Generate a PKCE code_verifier and its S256 code_challenge."""
    code_verifier = secrets.token_urlsafe(64)  # 86 chars, within limits
    sha256_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode()
    return code_verifier, code_challenge


def _create_auth_code_record(
    db,
    code_challenge: str,
    state: str,
    provider: str,
) -> str:
    """Persist PKCE challenge + CSRF state; returns the auth_code id.

    The caller-passed `state` (csrf_state) is stored in the DB and must be
    echoed back by the IdP for CSRF verification on callback.
    """
    from kubetix_api.models import AuthCode

    auth_code_id = secrets.token_urlsafe(16)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    record = AuthCode(
        id=auth_code_id,
        code_challenge=code_challenge,
        state=state,
        provider=provider,
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record.id


def _verify_auth_code(
    db,
    received_state: str,
    code_verifier: str,
) -> bool:
    """Verify CSRF state + PKCE challenge, mark used, return True on success.

    Looks up the AuthCode record by its stored `state` field (the CSRF token
    echoed back by the IdP), then verifies the PKCE code verifier.
    """
    from kubetix_api.models import AuthCode

    now = datetime.now(timezone.utc)
    record = (
        db.query(AuthCode)
        .filter(
            AuthCode.state == received_state,
            AuthCode.used == False,
            AuthCode.expires_at > now,
        )
        .first()
    )
    if record is None:
        return False

    sha256_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode()
    if computed_challenge != record.code_challenge:
        return False

    record.used = True
    db.commit()
    return True
