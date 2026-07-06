"""Pydantic request/response schemas for KubeTix API."""

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# RFC 5322 simplified email regex (covers common valid formats)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Kubernetes DNS subdomain (RFC 1123): lowercase alphanumeric + hyphens,
# must start/end with alphanumeric, max 253 chars.
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,251}[a-z0-9])?$")

# Valid grant roles (enum)
_GRANT_ROLES = {"view", "edit", "admin"}

# Valid team member roles (enum)
_TEAM_MEMBER_ROLES = {"owner", "admin", "member"}


def _is_valid_email(value: str) -> str:
    """Validate email format. Raises ValueError on failure."""
    if not value or len(value) > 254:
        raise ValueError("Email must be between 1 and 254 characters")
    if not _EMAIL_RE.match(value):
        raise ValueError("Invalid email format. Example: user@example.com")
    # Reject consecutive dots
    if ".." in value:
        raise ValueError("Email must not contain consecutive dots")
    return value


def _is_valid_k8s_name(value: str) -> str:
    """Validate Kubernetes DNS subdomain name (RFC 1123)."""
    if not value or len(value) > 253:
        raise ValueError("Name must be between 1 and 253 characters")
    if not _K8S_NAME_RE.match(value):
        raise ValueError(
            "Name must contain only lowercase letters, numbers, and hyphens. "
            "Must start and end with a letter or number."
        )
    return value


def _is_valid_password(value: str) -> str:
    """Validate password strength."""
    if not value or len(value) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return value


# ---------------------------------------------------------------------------
# User schemas
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    password: str
    full_name: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _is_valid_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _is_valid_password(v)


class UserLogin(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _is_valid_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _is_valid_password(v)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Grant schemas
# ---------------------------------------------------------------------------


class GrantCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cluster_name: str
    namespace: Optional[str] = None
    role: str = "view"
    expiry_hours: int = 4

    @field_validator("cluster_name")
    @classmethod
    def validate_cluster_name(cls, v: str) -> str:
        return _is_valid_k8s_name(v)

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _is_valid_k8s_name(v)
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in _GRANT_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(_GRANT_ROLES))}")
        return v

    @field_validator("expiry_hours")
    @classmethod
    def validate_expiry_hours(cls, v: int) -> int:
        if v < 1 or v > 720:
            raise ValueError("Expiry must be between 1 and 720 hours")
        return v


class GrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    cluster_name: str
    namespace: Optional[str] = None
    role: str
    expires_at: datetime
    revoked: bool
    created_at: datetime


class GrantWithKubeconfig(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    cluster_name: str
    namespace: Optional[str] = None
    role: str
    expires_at: datetime
    kubeconfig: str


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------


class Token(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    token_type: str
    user: UserResponse


# ---------------------------------------------------------------------------
# Team schemas
# ---------------------------------------------------------------------------


class TeamCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or len(v) > 253:
            raise ValueError("Team name must be between 1 and 253 characters")
        return _is_valid_k8s_name(v)


class TeamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    created_by: str
    created_at: datetime


class TeamMemberCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    role: str = "member"  # owner, admin, member

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _is_valid_email(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in _TEAM_MEMBER_ROLES:
            raise ValueError(
                f"Role must be one of: {', '.join(sorted(_TEAM_MEMBER_ROLES))}"
            )
        return v


class TeamMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    joined_at: datetime
