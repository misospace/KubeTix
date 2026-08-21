"""OIDC / SSO helpers — token exchange, PKCE, user provisioning."""

import hashlib
import base64
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, Depends, status
from jose import jwt, jwk
from jose.exceptions import JWTError, JWSError, JWTClaimsError

from kubetix_api.database import get_db, SessionLocal
from kubetix_api.auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from kubetix_api.models import User, provision_user

# ---------------------------------------------------------------------------
# ID token validation (signature + iss / aud / exp / nbf)
# ---------------------------------------------------------------------------

# Algorithms accepted for OIDC ID tokens. ``none`` is deliberately excluded:
# tokens without a signature (alg == "none") are never trusted, regardless of
# claims. Only asymmetric algorithms are listed because OIDC providers sign
# ID tokens with their published JWKS.
_ALLOWED_ID_TOKEN_ALGS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
)

# In-process JWKS cache keyed by ``jwks_uri``; value is ``(fetched_at, jwks)``.
_JWKS_CACHE: dict[str, tuple[float, dict]] = {}
_JWKS_CACHE_LOCK = threading.Lock()
_JWKS_CACHE_TTL_SECONDS = 3600.0


def _fetch_jwks(issuer: str, jwks_uri_override: Optional[str] = None) -> dict:
    """Return the provider's JWKS document for ``issuer`` (cached).

    The JWKS URI is resolved from the OIDC Discovery document
    (``{issuer}/.well-known/openid-configuration``) which is fetched by
    :func:`_fetch_oidc_discovery`. Results are cached per ``jwks_uri`` for
    :data:`_JWKS_CACHE_TTL_SECONDS` seconds so repeated SSO callbacks do not
    hammer the provider.

    ``jwks_uri_override`` lets callers (notably tests) point verification at
    a local JWKS without changing the configured issuer.
    """
    import httpx

    if jwks_uri_override:
        jwks_uri = jwks_uri_override
    else:
        discovery = _fetch_oidc_discovery(issuer) or {}
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"OIDC discovery for {issuer!r} did not advertise a "
                    "jwks_uri; cannot verify ID token signature"
                ),
            )

    now = time.monotonic()
    with _JWKS_CACHE_LOCK:
        cached = _JWKS_CACHE.get(jwks_uri)
        if cached and (now - cached[0]) < _JWKS_CACHE_TTL_SECONDS:
            return cached[1]

    try:
        response = httpx.get(jwks_uri, timeout=_OIDC_DISCOVERY_TIMEOUT_SECONDS)
        response.raise_for_status()
        jwks = response.json()
    except Exception as exc:  # noqa: BLE001 — surface as HTTP 502 for caller
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch JWKS from {jwks_uri!r}: {exc}",
        ) from exc

    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Malformed JWKS document from {jwks_uri!r}",
        )

    with _JWKS_CACHE_LOCK:
        _JWKS_CACHE[jwks_uri] = (time.monotonic(), jwks)
    return jwks


def _select_jwk(jwks: dict, kid: Optional[str], alg: str) -> dict:
    """Pick a JWK from ``jwks`` matching ``kid`` (or the only key if none)."""
    keys = jwks.get("keys", [])
    if kid is None:
        if len(keys) == 1:
            return keys[0]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID token header missing 'kid' and JWKS has multiple keys",
        )

    for key in keys:
        if key.get("kid") == kid:
            return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"No JWKS key matches ID token kid {kid!r}",
    )


def _validate_id_token(
    id_token: str,
    issuer: str,
    client_id: str,
    jwks_uri_override: Optional[str] = None,
) -> dict:
    """Verify the OIDC ID token signature and standard claims.

    The signature is verified against the provider's JWKS (resolved via the
    OIDC Discovery document's ``jwks_uri`` and cached in-process), and the
    ``alg``, ``iss``, ``aud``, ``exp``, and ``nbf`` claims are validated by
    :func:`jose.jwt.decode`. Tokens with ``alg == "none"`` or any algorithm
    outside :data:`_ALLOWED_ID_TOKEN_ALGS` are rejected before key lookup.

    ``jwks_uri_override`` lets callers (notably tests) point verification at
    a local JWKS without changing the configured issuer.

    Returns the decoded payload on success. Raises ``HTTPException`` on any
    failure (malformed token, missing/unsupported ``kid``, signature mismatch,
    claim mismatch, expired token, etc.).
    """
    # 1. Inspect the header so we know which algorithm the token claims and
    #    which key (by kid) to look up in the JWKS.
    try:
        header = jwt.get_unverified_header(id_token)
    except (JWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ID token header: {exc}",
        ) from exc

    alg = header.get("alg")
    if not alg or (isinstance(alg, str) and alg.lower() == "none"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID token is unsigned (alg=none); refusing to trust claims",
        )
    if alg not in _ALLOWED_ID_TOKEN_ALGS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unexpected ID token algorithm {alg!r}; refusing to verify",
        )

    kid = header.get("kid")

    # 2. Resolve the provider's JWKS and pick the matching key.
    jwks = _fetch_jwks(issuer, jwks_uri_override=jwks_uri_override)
    jwk_dict = _select_jwk(jwks, kid, alg)
    try:
        key = jwk.construct(jwk_dict, algorithm=alg)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not construct JWK for kid {kid!r}: {exc}",
        ) from exc

    # python-jose JWK objects expose the PEM-encoded public key via
    # ``to_pem()`` (PEM bytes, ``str`` for some backends). On the
    # cryptography backend, ``public_key`` is a bound method that returns
    # the cryptography ``RSAPublicKey`` itself, which is not what
    # ``jwt.decode`` wants — it wants PEM. So use ``to_pem()`` directly.
    try:
        public_key_pem = key.to_pem()  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not extract public key from JWK: {exc}",
        ) from exc
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")

    # 3. Verify signature + standard claims (iss, aud, exp, nbf) in one shot.
    #    ``jose.jwt.decode`` raises ``JWTError`` on any mismatch. We
    #    distinguish the kind of failure so the caller sees the right HTTP
    #    status: signature / key failures are authentication failures
    #    (401), while structural claim mismatches are bad-input failures
    #    (400) consistent with the pre-verification behavior.
    #
    #    Note: python-jose's ``verify_aud`` only checks the value when an
    #    ``aud`` claim exists; it does NOT reject a token that omits ``aud``
    #    entirely when ``audience`` is supplied. We require ``aud``
    #    presence explicitly via ``require_aud`` so a token that simply
    #    doesn't carry an audience is rejected as malformed.
    try:
        payload = jwt.decode(
            id_token,
            public_key_pem,
            algorithms=list(_ALLOWED_ID_TOKEN_ALGS),
            audience=client_id,
            issuer=issuer,
            options={
                "verify_at_hash": False,
                "verify_aud": True,
                "require_aud": True,
            },
        )
    except JWSError as exc:
        # Signature did not match the JWKS key (or the key shape was
        # wrong for the algorithm). Authentication failure.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"ID token signature invalid: {exc}",
        ) from exc
    except JWTClaimsError as exc:
        # Signature is valid but ``iss``/``aud``/``exp``/``nbf`` did not
        # match — preserve the prior 400 + descriptive detail so callers
        # and tests can still inspect the cause.
        message = str(exc).lower()
        if "issuer" in message:
            detail = f"ID token issuer mismatch: {exc}"
        elif "audience" in message:
            detail = f"ID token audience mismatch: {exc}"
        elif "expire" in message or "exp" in message:
            detail = f"ID token expired: {exc}"
        elif "not yet" in message or "nbf" in message or "immature" in message:
            detail = f"ID token not yet valid: {exc}"
        elif "aud" in message:
            detail = f"ID token missing 'aud' claim: {exc}"
        else:
            detail = f"ID token claims invalid: {exc}"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        ) from exc
    except JWTError as exc:
        # Token couldn't even be parsed by jose (malformed segments,
        # missing required claims, etc.). Bad-input failure.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ID token: {exc}",
        ) from exc

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
