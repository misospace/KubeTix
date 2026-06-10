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
from datetime import timedelta
from typing import List

import secrets

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status

# ---------------------------------------------------------------------------
# Rate limiting (optional)
# ---------------------------------------------------------------------------

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    HAS_RATE_LIMITING = True
except ImportError:
    HAS_RATE_LIMITING = False

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
from fastapi.middleware.cors import CORSMiddleware

_CORS_ORIGINS_RAW = os.environ.get("KUBETIX_CORS_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS = [o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="KubeTix API",
    description="Temporary Kubernetes Access Manager",
    version="0.1.0",
)

if HAS_RATE_LIMITING:
    limiter = Limiter(
        key_func=get_remote_address, default_limits=["200 per day", "50 per hour"]
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Register slowapi startup handler (compatible with all FastAPI versions)
    if hasattr(app, "add_event_handler"):
        app.add_event_handler("startup", limiter.slowapi_startup)
    else:
        app.on_event("startup")(limiter.slowapi_startup)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event():
    from kubetix_api.database import init_db
    import os as _os

    # Skip init_db in test mode — conftest handles table creation
    if not _os.environ.get("TESTING"):
        init_db()

    _admin_password = _os.environ.get("INITIAL_ADMIN_PASSWORD", "").strip()
    if not _admin_password:
        import logging

        logging.warning(
            "KubeTix startup: no INITIAL_ADMIN_PASSWORD set. "
            "The API will run without a default admin account. "
            "Create the first admin via /users registration or by setting "
            "INITIAL_ADMIN_PASSWORD=<strong-password> in production."
        )
        return

    from kubetix_api.database import SessionLocal
    from kubetix_api.models import User
    from kubetix_api.auth import get_password_hash

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@kubetix.local").first()
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


# ---------------------------------------------------------------------------
# Re-export shared dependencies for route handlers and tests
# ---------------------------------------------------------------------------

from kubetix_api.database import get_db  # noqa: E402
from kubetix_api.auth import (  # noqa: E402
    get_current_user,
    get_password_hash,
    create_access_token,
    verify_password,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)  # noqa: E402
from kubetix_api.models import (  # noqa: E402,F401
    Base,
    User,
    Team,
    TeamMember,
    AuthCode,
    Grant,
    AuditLog,
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


@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5 per hour") if HAS_RATE_LIMITING else (lambda x: x)
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


@app.post("/login", response_model=Token)
@limiter.limit("10 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def login(
    request: Request,
    user_data: UserLogin,
    db=Depends(get_db),
):
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

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
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
)


@app.get("/grants", response_model=List[GrantResponse])
@limiter.limit("10 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def list_grants(
    request: Request, current_user: User = Depends(get_current_user), db=Depends(get_db)
):
    return list_grants_for_user(current_user, db)


@app.post("/grants", response_model=GrantResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10 per hour") if HAS_RATE_LIMITING else (lambda x: x)
async def create_grant_endpoint(
    request: Request,
    grant_data: GrantCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return create_grant(grant_data, current_user, db)


@app.get("/grants/{grant_id}/download", response_model=GrantWithKubeconfig)
@limiter.limit("10 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def download_grant(
    request: Request,
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return get_grant(grant_id, current_user, db)


@app.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def revoke_grant_endpoint(
    request: Request,
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    revoke_grant(grant_id, current_user, db)


@app.get("/audit", response_model=List[dict])
async def get_audit_log_endpoint(
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


@app.post("/teams", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team_endpoint(
    team_data: TeamCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return create_team(team_data, current_user, db)


@app.get("/teams", response_model=List[TeamResponse])
async def list_teams_endpoint(
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return list_teams(current_user, db)


@app.get("/teams/{team_id}", response_model=TeamResponse)
async def get_team_endpoint(
    team_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return get_team(team_id, current_user, db)


@app.post("/teams/{team_id}/members", response_model=TeamMemberResponse)
async def add_team_member_endpoint(
    team_id: str,
    member_data: TeamMemberCreate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    return add_team_member(team_id, member_data, current_user, db)


@app.delete(
    "/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_team_member_endpoint(
    team_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    remove_team_member(team_id, user_id, current_user, db)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/teams/{team_id}/members", response_model=List[TeamMemberResponse])
async def list_team_members_endpoint(
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


@app.post("/auth/sso/callback")
@limiter.limit("5 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def sso_callback(
    request: Request,
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
    auth_code_id = request.query_params.get("state", "")
    code_verifier = request.query_params.get("code_verifier", "")
    if not auth_code_id or not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameters: state and code_verifier",
        )
    if not _verify_auth_code(db, auth_code_id, auth_code_id, code_verifier):
        raise HTTPException(
            status_code=400, detail="Invalid or expired authorization state"
        )

    redirect_uri = os.environ.get(
        "SSO_REDIRECT_URI",
        f"http://localhost:8000/auth/sso/callback?provider={provider}",
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
            status_code=401, detail="Failed to exchange authorization code for token"
        )

    token_data = resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=401, detail="No access token received from provider"
        )

    headers = (
        {"Authorization": f"Bearer {access_token}"}
        if provider != "github"
        else {"Authorization": f"token {access_token}", "Accept": "application/json"}
    )
    userinfo_resp = httpx.get(cfg["userinfo_url"], headers=headers, timeout=10)
    if userinfo_resp.status_code != 200:
        raise HTTPException(
            status_code=401, detail="Failed to fetch user information from provider"
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

    sso_id = str(
        userinfo.get("sub") or userinfo.get("id") or userinfo.get("github_id", "")
    )

    from kubetix_api.models import provision_user

    user = provision_user(
        db, email=email, full_name=full_name, sso_provider=provider, sso_id=sso_id
    )

    access_token_jwt = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {"access_token": access_token_jwt, "token_type": "bearer", "user": user}


@app.get("/auth/sso/{provider}/login")
async def sso_login(provider: str):
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

    from kubetix_api.database import SessionLocal

    db = SessionLocal()
    try:
        auth_code_id = _create_auth_code_record(
            db, code_challenge, csrf_state, provider
        )
    finally:
        db.close()

    redirect_uri = os.environ.get(
        "SSO_REDIRECT_URI",
        f"http://localhost:8000/auth/sso/callback?provider={provider}",
    )

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": cfg["scope"],
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": auth_code_id,
    }

    auth_url = f"{cfg['auth_url']}?{urllib.parse.urlencode(params)}"

    return {
        "provider": provider,
        "auth_url": auth_url,
        "code_verifier": code_verifier,
        "message": "Redirect user to auth_url; store code_verifier for the callback",
    }


@app.post("/auth/oidc/callback")
@limiter.limit("5 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def oidc_callback(
    request: Request,
    code: str,
    db=Depends(get_db),
):
    """Generic OIDC callback endpoint."""
    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri = os.environ.get(
        "OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback"
    )

    if not all([oidc_issuer, oidc_client_id, oidc_client_secret]):
        raise HTTPException(
            status_code=500,
            detail="OIDC not configured. Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET",
        )

    auth_code_id = request.query_params.get("state", "")
    code_verifier = request.query_params.get("code_verifier", "")
    if not auth_code_id or not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameters: state and code_verifier",
        )
    if not _verify_auth_code(db, auth_code_id, auth_code_id, code_verifier):
        raise HTTPException(
            status_code=400, detail="Invalid or expired authorization state"
        )

    try:
        token_data = _exchange_code_for_tokens(
            oidc_issuer, oidc_client_id, oidc_client_secret, code, oidc_redirect_uri
        )
    except Exception:
        raise HTTPException(
            status_code=401, detail="Failed to exchange authorization code for token"
        )

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=401, detail="No access token received from OIDC provider"
        )

    try:
        userinfo = _get_userinfo(issuer=oidc_issuer, access_token=access_token)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Failed to fetch user information from OIDC provider",
        )

    email = userinfo.get("email")
    if not email:
        raise HTTPException(
            status_code=401, detail="OIDC provider did not return an email address"
        )

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

    return {"access_token": access_token_jwt, "token_type": "bearer", "user": user}


@app.get("/auth/oidc/login")
async def oidc_login():
    """Initiate OIDC login with configured provider."""
    import urllib.parse

    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_redirect_uri = os.environ.get(
        "OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback"
    )

    if not oidc_issuer or not oidc_client_id:
        raise HTTPException(
            status_code=400,
            detail="OIDC not configured. Set OIDC_ISSUER and OIDC_CLIENT_ID.",
        )

    code_verifier, code_challenge = _generate_pkce_params()
    csrf_state = __import__("secrets").token_urlsafe(32)

    from kubetix_api.database import SessionLocal

    db = SessionLocal()
    try:
        auth_code_id = _create_auth_code_record(db, code_challenge, csrf_state, "oidc")
    finally:
        db.close()

    params = {
        "client_id": oidc_client_id,
        "redirect_uri": oidc_redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": auth_code_id,
    }

    auth_url = f"{oidc_issuer.rstrip('/')}/authorize?{urllib.parse.urlencode(params)}"

    return {
        "auth_url": auth_url,
        "code_verifier": code_verifier,
        "message": "Redirect user to auth_url; store code_verifier for the callback",
    }


@app.get("/auth/oidc/userinfo")
async def oidc_userinfo(current_user: User = Depends(get_current_user)):
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


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "0.1.0"}
