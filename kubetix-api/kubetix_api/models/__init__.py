"""SQLAlchemy ORM models for KubeTix."""

import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

Base = declarative_base()


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class User(Base):  # noqa: N801
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # NULL for SSO users
    full_name = Column(String(255))
    is_admin = Column(Boolean, default=False)
    sso_provider = Column(String(50), nullable=True)
    sso_id = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Team(Base):  # noqa: N801
    __tablename__ = "teams"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    created_by = Column(String(36), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class TeamMember(Base):  # noqa: N801
    __tablename__ = "team_members"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    team_id = Column(String(36), nullable=False)
    user_id = Column(String(36), nullable=False)
    role = Column(String(50), nullable=False)  # owner, admin, member
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_user"),
    )


class AuthCode(Base):  # noqa: N801
    """Store PKCE code_challenge + CSRF state for OAuth/OIDC flows.

    Records expire after 10 minutes and are marked used on successful callback.
    """
    __tablename__ = "auth_codes"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    code_challenge = Column(String(128), nullable=False)
    state = Column(String(128), nullable=False)
    provider = Column(String(50), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Grant(Base):  # noqa: N801
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


class AuditLog(Base):  # noqa: N801
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: secrets.token_urlsafe(16))
    user_id = Column(String(36), nullable=False)
    grant_id = Column(String(36), nullable=True)
    action = Column(String(50), nullable=False)
    details = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Helpers that depend on ORM models (used by auth/oidc modules)
# ---------------------------------------------------------------------------

def get_user_by_email(db: Session, email: str) -> "User | None":
    """Convenience: look up a user by email."""
    return db.query(User).filter(User.email == email).first()


def provision_user(
    db: Session,
    email: str,
    full_name: str | None,
    sso_provider: str,
    sso_id: str | None = None,
) -> User:
    """Create or update a user provisioned via SSO/OIDC. Returns the user."""
    from kubetix_api.models import User as UserModel

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if user is None:
        user = UserModel(
            id=secrets.token_urlsafe(16),
            email=email,
            hashed_password=None,  # SSO-only user
            full_name=full_name,
            sso_provider=sso_provider,
            sso_id=sso_id,
        )
        db.add(user)
    else:
        if user.sso_provider is None:
            user.sso_provider = sso_provider
            user.sso_id = sso_id
        if full_name and not user.full_name:
            user.full_name = full_name
    db.commit()
    db.refresh(user)
    return user
