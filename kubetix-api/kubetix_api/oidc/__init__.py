"""OIDC / SSO helpers — token exchange, PKCE, user provisioning."""

import hashlib
import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, Depends, status
from jose import jwt
from jose.exceptions import JWTError

from kubetix_api.database import get_db, SessionLocal
from kubetix_api.auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from kubetix_api.models import User, provision_user

# ---------------------------------------------------------------------------
# ID token validation (iss / aud)
# ---------------------------------------------------------------------------


def _validate_id_token(id_token: str, issuer: str, client_id: str) -> dict:
    """Decode an OIDC ID token and validate ``iss`` and ``aud`` claims.

    Returns the decoded payload on success. Raises ``HTTPException`` if the
    token is malformed or its claims do not match the configured issuer /
    client id.
    """
    try:
        # Decode without signature verification (we rely on the provider's
        # transport security; full JWK-based verification would require
        # fetching and caching the JWKS endpoint). We still validate the
        # structural claims that protect against token misuse.
        payload = jwt.get_unverified_claims(id_token)
    except (JWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ID token: {exc}",
        )

    token_issuer = payload.get("iss")
    if token_issuer != issuer:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ID token issuer mismatch: expected {issuer!r}, got {token_issuer!r}",
        )

    aud = payload.get("aud")
    if aud is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID token missing 'aud' claim",
        )
    # ``aud`` can be a string or a list of strings per OIDC spec.
    if isinstance(aud, str):
        aud_list = [aud]
    else:
        aud_list = aud
    if client_id not in aud_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ID token audience mismatch: expected {client_id!r}, got {aud_list}",
        )

    return payload


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# When True (default), SSO/OIDC provisioning requires ``email_verified`` to
# be present and truthy in the userinfo / ID token response. Set to ``false``
# only for providers that do not support this claim (e.g., legacy IdPs).
SSO_REQUIRE_EMAIL_VERIFIED = os.environ.get(
    "SSO_REQUIRE_EMAIL_VERIFIED", "true"
).lower() not in ("false", "0", "no")


def _email_verification_required() -> bool:
    """Return whether the SSO/OIDC callback should require ``email_verified``.

    Reads ``SSO_REQUIRE_EMAIL_VERIFIED`` from the process environment on each
    call so that ``os.environ`` changes (e.g. ``monkeypatch.setenv`` in tests,
    runtime config reloads) take effect without requiring a module reload.
    The module-level ``SSO_REQUIRE_EMAIL_VERIFIED`` constant above remains the
    default value at import time and is still exported for callers that want
    a snapshot.
    """
    return os.environ.get("SSO_REQUIRE_EMAIL_VERIFIED", "true").lower() not in (
        "false",
        "0",
        "no",
    )


def _check_email_verified(userinfo: dict, provider_name: str) -> None:
    """Raise ``HTTPException`` if the email is not verified.

    When ``SSO_REQUIRE_EMAIL_VERIFIED`` is enabled (the default), the
    userinfo response must contain ``email_verified`` set to a truthy value.
    If the claim is absent, we treat it as unverified for safety.
    """
    if not _email_verification_required():
        return

    email_verified = userinfo.get("email_verified")
    if not email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Email not verified by {provider_name}. "
                "Please verify your email address with the identity provider "
                "and try again."
            ),
        )


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
