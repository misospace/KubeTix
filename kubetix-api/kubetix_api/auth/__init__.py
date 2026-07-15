"""Authentication helpers — password hashing, JWT tokens, user resolution."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import HTTPException, Header, Depends, Request, Response, status
from jose import JWTError, jwt

from kubetix_api.database import get_db
from kubetix_api.models import User

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get("KUBETIX_SECRET_KEY") or __import__(
    "secrets"
).token_urlsafe(32)
ALGORITHM = "HS256"
# Short-lived access token. There is no refresh token or revocation
# mechanism beyond the in-memory blacklist, so the lifetime must remain
# small enough that a stolen token has a limited blast radius.
# 15 minutes is the conventional short-lived access token duration
# (OWASP JWT cheat sheet).
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # 15 minutes

# ---------------------------------------------------------------------------
# Cookie-based auth (httpOnly + Secure)
#
# Storing the JWT in localStorage / sessionStorage exposes it to any XSS
# payload (audit #144). The browser-side mitigation is to keep the JWT in
# an httpOnly + Secure + SameSite cookie so JavaScript cannot read it,
# while the backend keeps issuing short-lived bearer tokens for non-browser
# clients (CLI / dev token endpoint).
# ---------------------------------------------------------------------------

AUTH_COOKIE_NAME = "kubetix_session"
# "lax" lets top-level navigations from external IdPs carry the cookie
# while still blocking cross-site CSRF on state-changing requests.
AUTH_COOKIE_SAMESITE = "lax"


def set_auth_cookie(response: Response, token: str) -> None:
    """Attach the JWT as an httpOnly + Secure cookie on the response."""
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite=AUTH_COOKIE_SAMESITE,
        path="/",
    )


def clear_auth_cookie(response: Response) -> None:
    """Remove the JWT cookie (used by /auth/logout)."""
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path="/",
        samesite=AUTH_COOKIE_SAMESITE,
    )


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# ---------------------------------------------------------------------------
# Token blacklist (in-memory; survives within a single process lifetime)
# ---------------------------------------------------------------------------

_TOKEN_BLACKLIST: dict[str, datetime] = {}


def blacklist_token(jti: str, expires_at: datetime) -> None:
    """Add a token jti to the blacklist until it would have expired."""
    _TOKEN_BLACKLIST[jti] = expires_at


def is_blacklisted(jti: str) -> bool:
    """Check whether a token jti is blacklisted and not yet expired."""
    exp = _TOKEN_BLACKLIST.get(jti)
    if exp is None:
        return False
    if datetime.now(timezone.utc) >= exp:
        del _TOKEN_BLACKLIST[jti]
        return False
    return True


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "jti": secrets.token_urlsafe(16)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ---------------------------------------------------------------------------
# Current-user dependency
# ---------------------------------------------------------------------------


def _decode_payload(token: str) -> dict:
    """Decode and validate a JWT, raising HTTPException on failure."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    jti: str | None = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def get_current_user(
    request: Request,
    authorization: str | None = Header(None),
    db=Depends(get_db),
) -> User:
    """Resolve the authenticated user from a Bearer header OR the auth cookie.

    Accepting both keeps non-browser clients (CLI / dev token endpoint)
    working via ``Authorization: Bearer ...`` while the browser uses the
    httpOnly ``kubetix_session`` cookie (audit #144).
    """
    token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    else:
        token = request.cookies.get(AUTH_COOKIE_NAME)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _decode_payload(token)
    email: str | None = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def decode_token(token: str) -> dict:
    """Decode a JWT token and return its payload. Raises HTTPException on failure."""
    return _decode_payload(token)
