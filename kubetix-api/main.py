"""
KubeTix Backend API — modular entry point.

All business logic lives in sub-packages:
  - models   : SQLAlchemy ORM classes
  - schemas  : Pydantic request/response models
  - database : engine, sessions, init_db()
  - auth     : password hashing, JWT, current-user dependency
  - oidc     : PKCE, token exchange, SSO/OIDC helpers
  - grants   : grant CRUD + encryption
  - teams    : team CRUD
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import secrets

from fastapi import FastAPI, HTTPException, Header, Depends, Request, Response, status

# ---------------------------------------------------------------------------
# Rate limiting (optional)
# ---------------------------------------------------------------------------

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded


# ---------------------------------------------------------------------------
# Rate limiter key function: identify authenticated users by ID, fall back to
# proxy-aware client IP so one user cannot exhaust a shared bucket and one
# shared ingress IP cannot lock out the deployment.
# ---------------------------------------------------------------------------
def _rate_limit_key_func(request: Request) -> str:
    """Return a rate-limit key that prefers the authenticated user ID."""
    # Check for Authorization header to extract user identity
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from kubetix_api.auth import ALGORITHM, SECRET_KEY

            from jose import jwt

            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except Exception:
            pass

    # Fall back to proxy-aware client IP (X-Forwarded-For first hop, then X-Real-IP, then direct)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # First IP in the chain is the original client
        return f"ip:{forwarded_for.split(',')[0].strip()}"

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return f"ip:{real_ip.strip()}"

    client_host = request.client.host if request.client else "unknown"
    return f"ip:{client_host}"


limiter = Limiter(key_func=_rate_limit_key_func)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
from fastapi.middleware.cors import CORSMiddleware

# Resolved at app startup (see lifespan below) rather than at import time, so
# KUBETIX_CORS_ORIGINS env changes between module load and process start are
# honored without a full module reload. Mutated in-place so the CORSMiddleware
# instance — which holds a reference to this list — picks up new origins on
# the next request after startup.
ALLOWED_ORIGINS: list[str] = []


def _resolve_cors_origins(env: dict[str, str] | None = None) -> list[str]:
    """Parse KUBETIX_CORS_ORIGINS into a list of origins.

    Reads from the provided env mapping (defaults to os.environ) so tests can
    inject values without mutating the real environment.
    """
    src = env if env is not None else os.environ
    raw = src.get("KUBETIX_CORS_ORIGINS", "http://localhost:3000")
    return [o.strip() for o in raw.split(",") if o.strip()]


# ---------------------------------------------------------------------------
# App factory with lifespan (modern FastAPI pattern)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks.

    Replaces the deprecated @app.on_event("startup") pattern.
    See: https://fastapi.tiangolo.com/advanced/events/
    """
    # Startup
    from kubetix_api.database import init_db
    from kubetix_api.cleanup import run_grant_cleanup_loop
    import asyncio as _asyncio
    import os as _os

    # Populate CORS origins from the environment at startup, not at import.
    # Mutate in-place so the CORSMiddleware instance (constructed below with
    # a reference to this list) sees the resolved origins.
    ALLOWED_ORIGINS.clear()
    ALLOWED_ORIGINS.extend(_resolve_cors_origins())

    _cleanup_stop = _asyncio.Event()
    _cleanup_task = _asyncio.create_task(run_grant_cleanup_loop(_cleanup_stop))

    # Skip init_db in test mode — conftest handles table creation
    if not _os.environ.get("TESTING"):
        init_db()

    _admin_password = _os.environ.get("INITIAL_ADMIN_PASSWORD", "").strip()
    try:
        if not _admin_password:
            import logging

            logging.warning(
                "KubeTix startup: no INITIAL_ADMIN_PASSWORD set. "
                "The API will run without a default admin account. "
                "Create the first admin via /users registration or by setting "
                "INITIAL_ADMIN_PASSWORD=<strong-password> in production."
            )
        else:
            from kubetix_api.database import SessionLocal
            from kubetix_api.models import User
            from kubetix_api.auth import get_password_hash

            db = SessionLocal()
            try:
                admin = (
                    db.query(User).filter(User.email == "admin@kubetix.local").first()
                )
                if not admin:
                    admin = User(
                        id=__import__("secrets").token_urlsafe(16),
                        email="admin@kubetix.local",
                        hashed_password=get_password_hash(_admin_password),
                        full_name="Admin User",
                        is_admin=True,
                    )
                    db.add(admin)
                    db.commit()
            finally:
                db.close()
    finally:
        # Clear sensitive credential from the environment and local variable.
        _os.environ.pop("INITIAL_ADMIN_PASSWORD", None)
        _admin_password = ""
    yield
    # Shutdown: signal background tasks to stop and wait for them.
    _cleanup_stop.set()
    try:
        await _cleanup_task
    except Exception:  # pragma: no cover - defensive logging
        import logging as _logging

        _logging.getLogger(__name__).exception("Grant cleanup task errored on shutdown")


app = FastAPI(
    title="KubeTix API",
    description="Temporary Kubernetes Access Manager",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Versioned router for /api/v1/* routes
# ---------------------------------------------------------------------------
from fastapi import APIRouter

v1_router = APIRouter(prefix="/api/v1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Re-export shared dependencies for route handlers and tests
# ---------------------------------------------------------------------------

from kubetix_api.database import SessionLocal, get_db  # noqa: E402
from kubetix_api.auth import (  # noqa: E402
    get_current_user,
    get_password_hash,
    create_access_token,
    verify_password,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    decode_token,
)  # noqa: E402
from kubetix_api.models import (  # noqa: E402,F401
    Base,
    User,
    Team,
    TeamMember,
    AuthCode,
    Grant,
    AuditLog,
    BlacklistedToken,
)  # noqa: E402,F401
from kubetix_api.schemas import (  # noqa: E402
    UserCreate,
    UserLogin,
    UserResponse,
    GrantCreate,
    GrantResponse,
    GrantWithKubeconfig,
    Token,
    TeamCreate,
    TeamResponse,
    TeamMemberCreate,
    TeamMemberResponse,
)

# ---------------------------------------------------------------------------
# User endpoints
# ---------------------------------------------------------------------------


@v1_router.post(
    "/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("5 per hour")
async def register_user(
    request: Request,
    user_data: UserCreate,
    db=Depends(get_db),
):
    from kubetix_api.models import User as UserModel

    existing = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = UserModel(
        id=__import__("secrets").token_urlsafe(16),
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_admin=False,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@v1_router.post("/login", response_model=Token)
@limiter.limit("10 per minute")
async def login(
    request: Request,
    response: Response,
    user_data: UserLogin,
    db=Depends(get_db),
):
    from kubetix_api.auth import set_auth_cookie
    from kubetix_api.models import User as UserModel

    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if not user or user.hashed_password is None:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    # Issue the JWT as an httpOnly + Secure cookie so the browser never
    # has to keep it in JavaScript-readable storage (audit #144).
    set_auth_cookie(response, access_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@v1_router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10 per minute")
async def logout(
    request: Request,
    response: Response,
    authorization: str = Header(None),
):
    """Blacklist the current JWT so it cannot be reused and clear the auth cookie."""
    from kubetix_api.auth import blacklist_token, clear_auth_cookie, AUTH_COOKIE_NAME
    from kubetix_api.database import get_session_factory

    clear_auth_cookie(response)

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]
    payload = decode_token(token)
    jti: str | None = payload.get("jti")
    exp_raw: int | None = payload.get("exp")
    if jti and exp_raw is not None:
        expires_at = datetime.fromtimestamp(exp_raw, tz=timezone.utc)
        db = get_session_factory()()
        try:
            blacklist_token(jti, expires_at, db=db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


@v1_router.get("/users/me", response_model=UserResponse)
@limiter.limit("30 per minute")
async def get_current_user_info(
    request: Request, current_user: User = Depends(get_current_user)
):
    return current_user


# ---------------------------------------------------------------------------
# Grant endpoints
# ---------------------------------------------------------------------------

from kubetix_api.grants import (  # noqa: E402
    list_grants_for_user,
    create_grant,
    get_grant,
    revoke_grant,
    get_audit_log,
    update_grant,
)


@v1_router.get("/grants", response_model=List[GrantResponse])
@limiter.limit("10 per minute")
async def list_grants(
    request: Request, current_user: User = Depends(get_current_user), db=Depends(get_db)
):
    return list_grants_for_user(current_user, db)


@v1_router.post(
    "/grants", response_model=GrantResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("10 per hour")
async def create_grant_endpoint(
    request: Request,
    grant_data: GrantCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return create_grant(grant_data, current_user, db)


@v1_router.get("/grants/{grant_id}/download", response_model=GrantWithKubeconfig)
@limiter.limit("10 per minute")
async def download_grant(
    request: Request,
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return get_grant(grant_id, current_user, db)


@v1_router.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5 per minute")
async def revoke_grant_endpoint(
    request: Request,
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    revoke_grant(grant_id, current_user, db)


@v1_router.put("/grants/{grant_id}", response_model=GrantResponse)
def put_grant(
    grant_id: str,
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
):
    """Upsert/update a grant from the CLI ``sync`` bridge.

    The CLI emits a full record (id, created_at, expires_at, revoked,
    metadata, encrypted_kubeconfig, ...).  We accept the raw JSON body so
    the bridge can evolve without 422s, and dispatch to ``update_grant``
    which authorises on ownership / admin role and writes the row.
    """
    db = SessionLocal()
    try:
        return update_grant(grant_id, payload, current_user, db)
    finally:
        db.close()


@v1_router.get("/audit", response_model=List[dict])
@limiter.limit("20 per minute")
async def get_audit_log_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return get_audit_log(db, current_user)


# ---------------------------------------------------------------------------
# Team endpoints
# ---------------------------------------------------------------------------

from kubetix_api.teams import (  # noqa: E402
    create_team,
    list_teams,
    get_team,
    add_team_member,
    remove_team_member,
    list_team_members,
)


@v1_router.post(
    "/teams", response_model=TeamResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("10 per minute")
async def create_team_endpoint(
    request: Request,
    team_data: TeamCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return create_team(team_data, current_user, db)


@v1_router.get("/teams", response_model=List[TeamResponse])
@limiter.limit("30 per minute")
async def list_teams_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return list_teams(current_user, db)


@v1_router.get("/teams/{team_id}", response_model=TeamResponse)
@limiter.limit("30 per minute")
async def get_team_endpoint(
    request: Request,
    team_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return get_team(team_id, current_user, db)


@v1_router.post("/teams/{team_id}/members", response_model=TeamMemberResponse)
@limiter.limit("20 per minute")
async def add_team_member_endpoint(
    request: Request,
    team_id: str,
    member_data: TeamMemberCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return add_team_member(team_id, member_data, current_user, db)


@v1_router.delete(
    "/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
@limiter.limit("20 per minute")
async def remove_team_member_endpoint(
    request: Request,
    team_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    remove_team_member(team_id, user_id, current_user, db)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@v1_router.get("/teams/{team_id}/members", response_model=List[TeamMemberResponse])
@limiter.limit("30 per minute")
async def list_team_members_endpoint(
    request: Request,
    team_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return list_team_members(team_id, current_user, db)


# ---------------------------------------------------------------------------
# SSO / OIDC endpoints
# ---------------------------------------------------------------------------

from kubetix_api.oidc import (  # noqa: E402
    _generate_pkce_params,
    _create_auth_code_record,
    _verify_auth_code,
    _exchange_code_for_tokens,
    _get_userinfo,
)


@v1_router.get("/auth/sso/callback")
@limiter.limit("5 per minute")
async def sso_callback(
    request: Request,
    response: Response,
    provider: str,
    code: str,
    db=Depends(get_db),
):
    """Handle SSO callback from OAuth/OIDC providers."""
    import httpx

    provider_configs = {
        "google": {
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "client_id_env": "SSO_GOOGLE_CLIENT_ID",
            "client_secret_env": "SSO_GOOGLE_CLIENT_SECRET",
        },
        "github": {
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "client_id_env": "SSO_GITHUB_CLIENT_ID",
            "client_secret_env": "SSO_GITHUB_CLIENT_SECRET",
        },
        "okta": {
            "token_url": os.environ.get("SSO_OKTA_ISSUER", "").rstrip("/")
            + "/oauth2/default/v1/token",
            "userinfo_url": os.environ.get("SSO_OKTA_ISSUER", "").rstrip("/")
            + "/oauth2/default/v1/userinfo",
            "client_id_env": "SSO_OKTA_CLIENT_ID",
            "client_secret_env": "SSO_OKTA_CLIENT_SECRET",
        },
        "azure-ad": {
            "token_url": f"https://login.microsoftonline.com/{os.environ.get('SSO_AZURE_TENANT', '')}/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
            "client_id_env": "SSO_AZURE_CLIENT_ID",
            "client_secret_env": "SSO_AZURE_CLIENT_SECRET",
        },
        "authentik": {
            "token_url": os.environ.get("SSO_AUTHENTIK_ISSUER", "").rstrip("/")
            + "/application/o/token/",
            "userinfo_url": os.environ.get("SSO_AUTHENTIK_ISSUER", "").rstrip("/")
            + "/application/o/userinfo/",
            "client_id_env": "SSO_AUTHENTIK_CLIENT_ID",
            "client_secret_env": "SSO_AUTHENTIK_CLIENT_SECRET",
        },
    }

    if provider not in provider_configs:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider. Supported: {list(provider_configs.keys())}",
        )

    cfg = provider_configs[provider]
    client_id = os.environ.get(cfg["client_id_env"], "")
    client_secret = os.environ.get(cfg["client_secret_env"], "")

    if not all([client_id, client_secret]):
        raise HTTPException(
            status_code=500,
            detail=f"SSO provider '{provider}' is not configured. Set {cfg['client_id_env']} and {cfg['client_secret_env']}.",
        )

    # CSRF state + PKCE verification
    received_state = request.query_params.get("state", "")
    code_verifier = request.query_params.get("code_verifier", "")
    if not received_state or not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameters: state and code_verifier",
        )
    if not _verify_auth_code(db, received_state, code_verifier):
        raise HTTPException(
            status_code=400, detail="Invalid or expired authorization state"
        )

    redirect_uri = os.environ.get(
        "SSO_REDIRECT_URI",
        "http://localhost:8000/api/v1/auth/sso/callback",
    )

    if provider == "github":
        resp = httpx.post(
            cfg["token_url"],
            data={"client_id": client_id, "client_secret": client_secret, "code": code},
            headers={"Accept": "application/json"},
            timeout=10,
        )
    else:
        resp = httpx.post(
            cfg["token_url"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=10,
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail=f"Failed to exchange authorization code for token "
            f"(provider returned {resp.status_code}: {resp.text[:500]})",
        )

    token_data = resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=401, detail="No access token received from provider"
        )

    # Validate ID token iss/aud claims (if present — GitHub does not return one)
    id_token = token_data.get("id_token")
    if id_token:
        from kubetix_api.oidc import _validate_id_token

        issuer = cfg.get("issuer", "") or os.environ.get(
            "OIDC_ISSUER", "https://accounts.google.com"
        )
        _validate_id_token(id_token, issuer, client_id)

    headers = (
        {"Authorization": f"Bearer {access_token}"}
        if provider != "github"
        else {"Authorization": f"token {access_token}", "Accept": "application/json"}
    )
    userinfo_resp = httpx.get(cfg["userinfo_url"], headers=headers, timeout=10)
    if userinfo_resp.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail=f"Failed to fetch user information from provider "
            f"(provider returned {userinfo_resp.status_code}: {userinfo_resp.text[:500]})",
        )

    userinfo = userinfo_resp.json()

    # Provider-specific email extraction
    if provider == "google":
        email = userinfo.get("email")
        full_name = userinfo.get("name")
    elif provider == "github":
        email = userinfo.get("email") or f"{userinfo.get('login')}@github.com"
        full_name = userinfo.get("name")
    elif provider == "okta":
        email = userinfo.get("email")
        full_name = userinfo.get("name")
    elif provider == "azure-ad":
        email = (
            userinfo.get("email")
            or userinfo.get("mail")
            or userinfo.get("userPrincipalName")
        )
        full_name = userinfo.get("displayName")
    elif provider == "authentik":
        email = userinfo.get("email")
        full_name = userinfo.get("name")
    else:
        email = userinfo.get("email")

    if not email:
        raise HTTPException(
            status_code=401, detail="Provider did not return an email address"
        )

    # Verify email is confirmed by the provider (when supported)
    from kubetix_api.oidc import _check_email_verified

    _check_email_verified(userinfo, provider)

    sso_id = str(
        userinfo.get("sub") or userinfo.get("id") or userinfo.get("github_id", "")
    )

    from kubetix_api.auth import set_auth_cookie
    from kubetix_api.models import provision_user

    user = provision_user(
        db, email=email, full_name=full_name, sso_provider=provider, sso_id=sso_id
    )

    access_token_jwt = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    set_auth_cookie(response, access_token_jwt)

    return {"access_token": access_token_jwt, "token_type": "bearer", "user": user}


@v1_router.get("/auth/sso/{provider}/login")
@limiter.limit("10 per minute")
async def sso_login(
    request: Request,
    provider: str,
    db=Depends(get_db),
):
    """Initiate SSO login flow — returns auth URL + code_verifier."""
    import urllib.parse

    provider_configs = {
        "google": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "scope": "openid email profile",
        },
        "github": {
            "auth_url": "https://github.com/login/oauth/authorize",
            "scope": "user:email",
        },
        "okta": {
            "auth_url": f"{os.environ.get('SSO_OKTA_ISSUER', '{your-okta-domain}')}/oauth2/default/v1/authorize",
            "scope": "openid email profile",
        },
        "azure-ad": {
            "auth_url": f"https://login.microsoftonline.com/{os.environ.get('SSO_AZURE_TENANT', '{tenant}')}/oauth2/v2.0/authorize",
            "scope": "openid email profile https://graph.microsoft.com/User.Read",
        },
        "authentik": {
            "auth_url": f"{os.environ.get('SSO_AUTHENTIK_ISSUER', 'https://authentik.yourdomain.com')}/application/o/authorize/",
            "scope": "openid email profile",
        },
    }

    if provider not in provider_configs:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider. Supported: {list(provider_configs.keys())}",
        )

    cfg = provider_configs[provider]
    client_id = os.environ.get(f"SSO_{provider.upper()}_CLIENT_ID", "")

    if not client_id:
        raise HTTPException(
            status_code=400,
            detail=f"SSO provider '{provider}' is not configured. Set SSO_{provider.upper()}_CLIENT_ID.",
        )

    code_verifier, code_challenge = _generate_pkce_params()
    csrf_state = secrets.token_urlsafe(32)

    _create_auth_code_record(db, code_challenge, csrf_state, provider)

    redirect_uri = os.environ.get(
        "SSO_REDIRECT_URI",
        "http://localhost:8000/api/v1/auth/sso/callback",
    )

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": cfg["scope"],
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": csrf_state,
    }

    auth_url = f"{cfg['auth_url']}?{urllib.parse.urlencode(params)}"

    return {
        "provider": provider,
        "auth_url": auth_url,
        "code_verifier": code_verifier,
        "csrf_state": csrf_state,
        "message": "Redirect user to auth_url; store code_verifier for the callback",
    }


@v1_router.get("/auth/oidc/callback")
@limiter.limit("5 per minute")
async def oidc_callback(
    request: Request,
    response: Response,
    code: str,
    db=Depends(get_db),
):
    """Generic OIDC callback endpoint."""
    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri = os.environ.get(
        "OIDC_REDIRECT_URI", "http://localhost:8000/api/v1/auth/oidc/callback"
    )

    if not all([oidc_issuer, oidc_client_id, oidc_client_secret]):
        raise HTTPException(
            status_code=500,
            detail="OIDC not configured. Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET",
        )

    received_state = request.query_params.get("state", "")
    code_verifier = request.query_params.get("code_verifier", "")
    if not received_state or not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameters: state and code_verifier",
        )
    if not _verify_auth_code(db, received_state, code_verifier):
        raise HTTPException(
            status_code=400, detail="Invalid or expired authorization state"
        )

    try:
        token_data = _exchange_code_for_tokens(
            oidc_issuer, oidc_client_id, oidc_client_secret, code, oidc_redirect_uri
        )
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Failed to exchange authorization code for token: {e}",
        )

    access_token = token_data.get("access_token")
    id_token = token_data.get("id_token")
    if not access_token:
        raise HTTPException(
            status_code=401, detail="No access token received from OIDC provider"
        )

    # Validate ID token iss/aud claims (if present)
    if id_token:
        from kubetix_api.oidc import _validate_id_token

        _validate_id_token(id_token, oidc_issuer, oidc_client_id)

    try:
        userinfo = _get_userinfo(issuer=oidc_issuer, access_token=access_token)
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Failed to fetch user information from OIDC provider: {e}",
        )

    email = userinfo.get("email")
    if not email:
        raise HTTPException(
            status_code=401, detail="OIDC provider did not return an email address"
        )

    # Verify email is confirmed by the provider (when supported)
    from kubetix_api.oidc import _check_email_verified

    _check_email_verified(userinfo, "OIDC provider")

    full_name = userinfo.get("name") or userinfo.get("preferred_username")
    sso_id = str(userinfo.get("sub", ""))

    from kubetix_api.models import provision_user

    user = provision_user(
        db, email=email, full_name=full_name, sso_provider="oidc", sso_id=sso_id
    )

    access_token_jwt = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    from kubetix_api.auth import set_auth_cookie

    set_auth_cookie(response, access_token_jwt)

    return {"access_token": access_token_jwt, "token_type": "bearer", "user": user}


@v1_router.get("/auth/oidc/login")
@limiter.limit("10 per minute")
async def oidc_login(
    request: Request,
    db=Depends(get_db),
):
    """Initiate OIDC login with configured provider."""
    import urllib.parse

    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_redirect_uri = os.environ.get(
        "OIDC_REDIRECT_URI", "http://localhost:8000/api/v1/auth/oidc/callback"
    )

    if not oidc_issuer or not oidc_client_id:
        raise HTTPException(
            status_code=400,
            detail="OIDC not configured. Set OIDC_ISSUER and OIDC_CLIENT_ID.",
        )

    code_verifier, code_challenge = _generate_pkce_params()
    csrf_state = __import__("secrets").token_urlsafe(32)

    _create_auth_code_record(db, code_challenge, csrf_state, "oidc")

    params = {
        "client_id": oidc_client_id,
        "redirect_uri": oidc_redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": csrf_state,
    }

    auth_url = f"{oidc_issuer.rstrip('/')}/authorize?{urllib.parse.urlencode(params)}"

    return {
        "auth_url": auth_url,
        "code_verifier": code_verifier,
        "csrf_state": csrf_state,
        "message": "Redirect user to auth_url; store code_verifier for the callback",
    }


@v1_router.get("/auth/oidc/userinfo")
@limiter.limit("30 per minute")
async def oidc_userinfo(
    request: Request, current_user: User = Depends(get_current_user)
):
    """Get current user info with OIDC attributes."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "sso_provider": current_user.sso_provider,
        "is_admin": current_user.is_admin,
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@v1_router.get("/health")
async def health_check():
    return {"status": "healthy", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# Mount versioned router
# ---------------------------------------------------------------------------
app.include_router(v1_router)

# ---------------------------------------------------------------------------
# Backward-compatible redirects (301) from old bare paths to /api/v1/*
# ---------------------------------------------------------------------------
from fastapi.responses import RedirectResponse


@app.get("/health")
async def redirect_health():
    return RedirectResponse(url="/api/v1/health", status_code=301)


@app.post("/login")
async def redirect_login():
    return RedirectResponse(url="/api/v1/login", status_code=301)


@app.post("/auth/logout")
async def redirect_logout():
    return RedirectResponse(url="/api/v1/auth/logout", status_code=301)


@app.get("/users")
async def redirect_users():
    return RedirectResponse(url="/api/v1/users", status_code=301)


@app.post("/users")
async def redirect_create_user():
    return RedirectResponse(url="/api/v1/users", status_code=301)


@app.get("/grants")
async def redirect_grants_list():
    return RedirectResponse(url="/api/v1/grants", status_code=301)


@app.post("/grants")
async def redirect_create_grant():
    return RedirectResponse(url="/api/v1/grants", status_code=301)


@app.get("/audit")
async def redirect_audit():
    return RedirectResponse(url="/api/v1/audit", status_code=301)


@app.post("/teams")
async def redirect_create_team():
    return RedirectResponse(url="/api/v1/teams", status_code=301)


@app.get("/auth/sso/callback")
async def redirect_sso_callback():
    return RedirectResponse(url="/api/v1/auth/sso/callback", status_code=301)


@app.post("/auth/sso/callback")
async def redirect_sso_callback_post():
    return RedirectResponse(url="/api/v1/auth/sso/callback", status_code=301)


@app.get("/auth/oidc/callback")
async def redirect_oidc_callback():
    return RedirectResponse(url="/api/v1/auth/oidc/callback", status_code=301)


@app.post("/auth/oidc/callback")
async def redirect_oidc_callback_post():
    return RedirectResponse(url="/api/v1/auth/oidc/callback", status_code=301)
