"""
KubeTix Backend API
FastAPI-based REST API for KubeTix
"""

import subprocess
import sys
import secrets
import sqlite3
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, String, Boolean, Text, DateTime, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import func

# Rate limiting support
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    
    HAS_RATE_LIMITING = True
except ImportError:
    HAS_RATE_LIMITING = False

# Authenticated encryption for kubeconfig storage
try:
    from cryptography.fernet import Fernet
except ImportError:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "cryptography"]
    )
    from cryptography.fernet import Fernet

_ENCRYPTION_KEY = os.environ.get("KUBECONFIG_ENCRYPTION_KEY") or None

# Configuration
SECRET_KEY = os.environ.get("KUBETIX_SECRET_KEY") or secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Database
DATABASE_URL = os.environ.get("DATABASE_URL") or "sqlite:///./kubetix.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# FastAPI app
app = FastAPI(
    title="KubeTix API",
    description="Temporary Kubernetes Access Manager",
    version="0.1.0"
)


# Rate limiter (initialized after app creation if slowapi is available)
limiter = None
if HAS_RATE_LIMITING:
    limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# CORS — locked to explicit origins (P0-1 fix)
# ---------------------------------------------------------------------------
# Allow multiple origins via comma-separated env var; falls back to a single
# localhost origin so the dev server still works without configuration.
_CORS_ORIGINS_RAW = os.environ.get("KUBETIX_CORS_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS = [
    o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# OIDC helpers (P0-2 fix — real token exchange & user provisioning)
# ---------------------------------------------------------------------------

def _oidc_endpoints(issuer: str) -> dict:
    """Return OIDC discovery endpoints for the given issuer."""
    return {
        "token_endpoint": f"{issuer.rstrip('/')}/oauth/token",
        "userinfo_endpoint": f"{issuer.rstrip('/')}/oauth/userinfo",
    }


def _exchange_code_for_tokens(issuer: str, client_id: str, client_secret: str,
                               code: str, redirect_uri: str) -> dict:
    """Exchange an authorization code for access + ID tokens via the token endpoint."""
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


def _provision_user(db: Session, email: str, full_name: Optional[str],
                    sso_provider: str, sso_id: Optional[str]) -> "User":
    """Create or update a user provisioned via SSO/OIDC. Returns the user."""
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        user = User(
            id=secrets.token_urlsafe(16),
            email=email,
            hashed_password=None,          # SSO-only user
            full_name=full_name,
            sso_provider=sso_provider,
            sso_id=sso_id,
        )
        db.add(user)
    else:
        # Update existing user if they don't yet have SSO attributes
        if user.sso_provider is None:
            user.sso_provider = sso_provider
            user.sso_id = sso_id
        if full_name and not user.full_name:
            user.full_name = full_name
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # NULL for SSO users
    full_name = Column(String(255))
    is_admin = Column(Boolean, default=False)
    sso_provider = Column(String(50), nullable=True)  # google, github, okta, etc.
    sso_id = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Team(Base):
    __tablename__ = "teams"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    created_by = Column(String(36), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class TeamMember(Base):
    __tablename__ = "team_members"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    team_id = Column(String(36), nullable=False)
    user_id = Column(String(36), nullable=False)
    role = Column(String(50), nullable=False)  # owner, admin, member
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        # Unique constraint: one role per user per team
        UniqueConstraint('team_id', 'user_id', name='uq_team_user'),
    )


class Grant(Base):
    __tablename__ = "grants"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    user_id = Column(String(36), nullable=False)
    cluster_name = Column(String(255), nullable=False)
    namespace = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False)
    encrypted_kubeconfig = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    user_id = Column(String(36), nullable=False)
    grant_id = Column(String(36), nullable=True)
    action = Column(String(50), nullable=False)
    details = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


class GrantCreate(BaseModel):
    cluster_name: str
    namespace: Optional[str] = None
    role: str = "view"
    expiry_hours: int = 4


class GrantResponse(BaseModel):
    id: str
    cluster_name: str
    namespace: Optional[str] = None
    role: str
    expires_at: datetime
    revoked: bool
    created_at: datetime

    class Config:
        from_attributes = True


class GrantWithKubeconfig(BaseModel):
    id: str
    cluster_name: str
    namespace: Optional[str] = None
    role: str
    expires_at: datetime
    kubeconfig: str


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# Team Models
class TeamCreate(BaseModel):
    name: str
    description: Optional[str] = None


class TeamResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class TeamMemberCreate(BaseModel):
    email: str
    role: str = "member"  # owner, admin, member


class TeamMemberResponse(BaseModel):
    id: str
    user_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    joined_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Database Functions
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Authentication Functions
# ---------------------------------------------------------------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    # Guard: reject missing or empty tokens before jwt.decode()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
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


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    init_db()
    # Create admin user if not exists
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@kubetix.local").first()
        if not admin:
            admin = User(
                id=secrets.token_urlsafe(16),
                email="admin@kubetix.local",
                hashed_password=get_password_hash("admin123"),
                full_name="Admin User",
                is_admin=True
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()


@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5 per hour") if HAS_RATE_LIMITING else (lambda x: x)
async def register_user(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    new_user = User(
        id=secrets.token_urlsafe(16),
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_admin=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/login", response_model=Token)
@limiter.limit("10 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def login(request: Request, user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()

    # Guard: SSO-only users cannot log in with a password
    if not user or user.hashed_password is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/grants", response_model=List[GrantResponse])
async def list_grants(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    grants = db.query(Grant).filter(
        Grant.user_id == current_user.id,
        Grant.revoked == False,
        Grant.expires_at > datetime.now(timezone.utc).replace(tzinfo=None)
    ).order_by(Grant.created_at.desc()).all()

    return grants


@app.post("/grants", response_model=GrantResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10 per hour") if HAS_RATE_LIMITING else (lambda x: x)
async def create_grant(
    request: Request,
    grant_data: GrantCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate role
    if grant_data.role not in ["view", "edit", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be view, edit, or admin"
        )

    # Validate expiry
    if grant_data.expiry_hours < 1 or grant_data.expiry_hours > 720:  # 1 hour to 30 days
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expiry must be between 1 and 720 hours"
        )

    # Get kubeconfig
    kubeconfig_path = os.environ.get("KUBECONFIG", Path.home() / ".kube" / "config")

    if not os.path.exists(kubeconfig_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Kubeconfig not found at {kubeconfig_path}"
        )

    with open(kubeconfig_path) as f:
        kubeconfig = f.read()

    # Encrypt kubeconfig with Fernet authenticated encryption.
    _key = os.environ.get("KUBECONFIG_ENCRYPTION_KEY") or _ENCRYPTION_KEY
    if not _key:
        _key = Fernet.generate_key().decode()
        import logging
        logging.warning(
            "KubeTix: no KUBECONFIG_ENCRYPTION_KEY set. Generated ephemeral key — "
            "existing grants will fail to decrypt after restart."
        )
    fernet = Fernet(_key.encode())
    encrypted_kubeconfig = fernet.encrypt(kubeconfig.encode()).decode()

    # Create grant
    expires_at = datetime.now(timezone.utc) + timedelta(hours=grant_data.expiry_hours)

    new_grant = Grant(
        id=secrets.token_urlsafe(16),
        user_id=current_user.id,
        cluster_name=grant_data.cluster_name,
        namespace=grant_data.namespace,
        role=grant_data.role,
        encrypted_kubeconfig=encrypted_kubeconfig,
        expires_at=expires_at
    )

    db.add(new_grant)

    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        grant_id=new_grant.id,
        action="created",
        details=f"Created grant for {grant_data.cluster_name}"
    )
    db.add(audit)

    db.commit()
    db.refresh(new_grant)

    return new_grant


@app.get("/grants/{grant_id}/download", response_model=GrantWithKubeconfig)
async def download_grant(
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    grant = db.query(Grant).filter(Grant.id == grant_id).first()

    if not grant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Grant not found"
        )

    if grant.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this grant"
        )

    if grant.revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Grant has been revoked"
        )

    expires_at = grant.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Grant has expired"
        )

    # Decrypt kubeconfig
    _key = os.environ.get("KUBECONFIG_ENCRYPTION_KEY") or _ENCRYPTION_KEY
    if not _key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption key not configured. Set KUBECONFIG_ENCRYPTION_KEY."
        )
    fernet = Fernet(_key.encode())
    kubeconfig = fernet.decrypt(grant.encrypted_kubeconfig.encode()).decode()

    return {
        "id": grant.id,
        "cluster_name": grant.cluster_name,
        "namespace": grant.namespace,
        "role": grant.role,
        "expires_at": grant.expires_at,
        "kubeconfig": kubeconfig
    }


@app.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_grant(
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    grant = db.query(Grant).filter(Grant.id == grant_id).first()

    if not grant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Grant not found"
        )

    # Only owner or admin can revoke
    if grant.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this grant"
        )

    grant.revoked = True
    db.commit()

    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        grant_id=grant_id,
        action="revoked",
        details="Manually revoked"
    )
    db.add(audit)
    db.commit()


@app.get("/audit", response_model=List[dict])
async def get_audit_log(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Admins see all logs, users see their own
    if current_user.is_admin:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    else:
        logs = db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id
        ).order_by(AuditLog.created_at.desc()).limit(100).all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "grant_id": log.grant_id,
            "action": log.action,
            "details": log.details,
            "created_at": log.created_at
        }
        for log in logs
    ]


# ---------------------------------------------------------------------------
# Team Endpoints
# ---------------------------------------------------------------------------

@app.post("/teams", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    team_data: TeamCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_team = Team(
        id=secrets.token_urlsafe(16),
        name=team_data.name,
        description=team_data.description,
        created_by=current_user.id
    )

    db.add(new_team)

    # Add creator as owner
    member = TeamMember(
        id=secrets.token_urlsafe(16),
        team_id=new_team.id,
        user_id=current_user.id,
        role="owner"
    )
    db.add(member)

    db.commit()
    db.refresh(new_team)

    return new_team


@app.get("/teams", response_model=List[TeamResponse])
async def list_teams(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Get all teams user is a member of
    from sqlalchemy import and_

    team_ids = db.query(TeamMember.team_id).filter(
        TeamMember.user_id == current_user.id
    ).subquery()

    teams = db.query(Team).filter(
        Team.id.in_(team_ids)
    ).order_by(Team.created_at.desc()).all()

    return teams


@app.get("/teams/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    team = db.query(Team).filter(Team.id == team_id).first()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    # Check if user is member
    member = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == current_user.id
    ).first()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this team"
        )

    return team


@app.post("/teams/{team_id}/members", response_model=TeamMemberResponse)
async def add_team_member(
    team_id: str,
    member_data: TeamMemberCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if user is owner or admin of team
    member = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == current_user.id
    ).first()

    if not member or member.role not in ["owner", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners and admins can add members"
        )

    # Find user by email
    target_user = db.query(User).filter(User.email == member_data.email).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if already a member
    existing = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == target_user.id
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member of this team"
        )

    # Add member
    new_member = TeamMember(
        id=secrets.token_urlsafe(16),
        team_id=team_id,
        user_id=target_user.id,
        role=member_data.role
    )

    db.add(new_member)
    db.commit()
    db.refresh(new_member)

    return new_member


@app.delete("/teams/{team_id}/members/{user_id}")
async def remove_team_member(
    team_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if user is owner of team
    member = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == current_user.id
    ).first()

    if not member or member.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners can remove members"
        )

    # Can't remove yourself
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the team"
        )

    # Remove member
    db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id
    ).delete()

    db.commit()


@app.get("/teams/{team_id}/members", response_model=List[TeamMemberResponse])
async def list_team_members(
    team_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if user is member
    member = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == current_user.id
    ).first()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this team"
        )

    members = db.query(TeamMember).filter(
        TeamMember.team_id == team_id
    ).join(User, TeamMember.user_id == User.id).all()

    return members


# ---------------------------------------------------------------------------
# SSO/Authentik/OIDC Endpoints — REAL implementations (P0-2 fix)
# ---------------------------------------------------------------------------

@app.post("/auth/sso/callback")
@limiter.limit("5 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def sso_callback(
    request: Request,
    provider: str,
    code: str,
    db: Session = Depends(get_db)
):
    """
    Handle SSO callback from OAuth/OIDC provider.
    Supports: Google, GitHub, Okta, Azure AD, Authentik

    Real implementation: exchanges the authorization code for tokens at the
    provider's token endpoint, fetches user info, provisions/updates the user
    in the local database, and returns a JWT access token.
    """
    # Map provider names to their configuration
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
            "token_url": os.environ.get("SSO_OKTA_ISSUER", "").rstrip("/") + "/oauth2/default/v1/token",
            "userinfo_url": os.environ.get("SSO_OKTA_ISSUER", "").rstrip("/") + "/oauth2/default/v1/userinfo",
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
            "token_url": os.environ.get("SSO_AUTHENTIK_ISSUER", "").rstrip("/") + "/application/o/token/",
            "userinfo_url": os.environ.get("SSO_AUTHENTIK_ISSUER", "").rstrip("/") + "/application/o/userinfo/",
            "client_id_env": "SSO_AUTHENTIK_CLIENT_ID",
            "client_secret_env": "SSO_AUTHENTIK_CLIENT_SECRET",
        },
    }

    if provider not in provider_configs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider. Supported: {list(provider_configs.keys())}"
        )

    cfg = provider_configs[provider]
    client_id = os.environ.get(cfg["client_id_env"], "")
    client_secret = os.environ.get(cfg["client_secret_env"], "")

    if not all([client_id, client_secret]):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSO provider '{provider}' is not configured. Set {cfg['client_id_env']} and {cfg['client_secret_env']}."
        )

    import httpx

    # Step 1: Exchange code for access token
    redirect_uri = os.environ.get("SSO_REDIRECT_URI", f"http://localhost:8000/auth/sso/callback?provider={provider}")

    if provider == "github":
        # GitHub uses a slightly different token exchange format
        resp = httpx.post(
            cfg["token_url"],
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
            },
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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to exchange code for token: {resp.text}"
        )

    token_data = resp.json()
    access_token = token_data.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No access token received from provider"
        )

    # Step 2: Fetch user info from provider
    headers = {"Authorization": f"Bearer {access_token}"} if provider != "github" else {}
    if provider == "github":
        headers = {"Authorization": f"token {access_token}", "Accept": "application/json"}

    userinfo_resp = httpx.get(cfg["userinfo_url"], headers=headers, timeout=10)
    if userinfo_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to fetch user info: {userinfo_resp.text}"
        )

    userinfo = userinfo_resp.json()

    # Step 3: Extract email (provider-specific)
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
        email = userinfo.get("email") or userinfo.get("mail") or userinfo.get("userPrincipalName")
        full_name = userinfo.get("displayName")
    elif provider == "authentik":
        email = userinfo.get("email")
        full_name = userinfo.get("name")
    else:
        email = userinfo.get("email")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provider did not return an email address"
        )

    # Step 4: Provision user in local DB
    sso_id = str(userinfo.get("sub") or userinfo.get("id") or userinfo.get("github_id", ""))
    user = _provision_user(db, email=email, full_name=full_name,
                          sso_provider=provider, sso_id=sso_id)

    # Step 5: Return JWT token
    access_token_jwt = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token_jwt,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/auth/sso/{provider}/login")
async def sso_login(provider: str):
    """
    Initiate SSO login flow.
    Returns the OAuth authorization URL to redirect the user to.
    """
    # Redirect URI for all SSO providers (provider-specific callback path)
    redirect_uri = os.environ.get(
        "SSO_REDIRECT_URI",
        f"http://localhost:8000/auth/sso/callback?provider={provider}"
    )

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
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider. Supported: {list(provider_configs.keys())}"
        )

    cfg = provider_configs[provider]
    client_id = os.environ.get(f"SSO_{provider.upper()}_CLIENT_ID", "")

    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSO provider '{provider}' is not configured. Set SSO_{provider.upper()}_CLIENT_ID."
        )

    import urllib.parse

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": cfg["scope"],
    }

    auth_url = f"{cfg['auth_url']}?{urllib.parse.urlencode(params)}"

    return {
        "provider": provider,
        "auth_url": auth_url,
        "message": "Redirect user to auth_url",
    }


@app.post("/auth/oidc/callback")
@limiter.limit("5 per minute") if HAS_RATE_LIMITING else (lambda x: x)
async def oidc_callback(
    request: Request,
    code: str,
    db: Session = Depends(get_db)
):
    """
    Generic OIDC callback endpoint.
    Works with any compliant OIDC provider (Authentik, Keycloak, Okta, etc.).

    Real implementation: exchanges the authorization code for tokens at the
    issuer's token endpoint, fetches user info, provisions/updates the user,
    and returns a JWT access token.
    """
    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback")

    if not all([oidc_issuer, oidc_client_id, oidc_client_secret]):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC not configured. Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET"
        )

    # Step 1: Exchange code for tokens at the issuer's token endpoint
    try:
        token_data = _exchange_code_for_tokens(
            issuer=oidc_issuer,
            client_id=oidc_client_id,
            client_secret=oidc_client_secret,
            code=code,
            redirect_uri=oidc_redirect_uri,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to exchange code for token: {exc}"
        )

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No access token received from OIDC provider"
        )

    # Step 2: Fetch user info
    try:
        userinfo = _get_userinfo(issuer=oidc_issuer, access_token=access_token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to fetch user info from OIDC provider: {exc}"
        )

    # Step 3: Extract email (standard OIDC claim)
    email = userinfo.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC provider did not return an email address"
        )

    full_name = userinfo.get("name") or userinfo.get("preferred_username")

    # Step 4: Provision user
    sso_id = str(userinfo.get("sub", ""))
    user = _provision_user(
        db, email=email, full_name=full_name,
        sso_provider="oidc", sso_id=sso_id,
    )

    # Step 5: Return JWT token
    access_token_jwt = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token_jwt,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/auth/oidc/login")
async def oidc_login():
    """
    Initiate OIDC login with configured provider.
    Redirects to the OIDC provider's authorization endpoint.
    """
    oidc_issuer = os.environ.get("OIDC_ISSUER", "")
    oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "")
    oidc_redirect_uri = os.environ.get(
        "OIDC_REDIRECT_URI",
        "http://localhost:8000/auth/oidc/callback"
    )

    if not oidc_issuer or not oidc_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC not configured. Set OIDC_ISSUER and OIDC_CLIENT_ID."
        )

    import urllib.parse

    params = {
        "client_id": oidc_client_id,
        "redirect_uri": oidc_redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
    }

    auth_url = f"{oidc_issuer.rstrip('/')}/authorize?{urllib.parse.urlencode(params)}"

    return {
        "auth_url": auth_url,
        "message": "Redirect user to auth_url",
    }


@app.get("/auth/oidc/userinfo")
async def oidc_userinfo(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user info with OIDC attributes.
    """
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "sso_provider": current_user.sso_provider,
        "is_admin": current_user.is_admin,
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "0.1.0"}
