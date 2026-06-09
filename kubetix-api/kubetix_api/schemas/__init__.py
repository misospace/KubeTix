"""Pydantic request/response schemas for KubeTix API."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# User schemas
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


# ---------------------------------------------------------------------------
# Grant schemas
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# ---------------------------------------------------------------------------
# Team schemas
# ---------------------------------------------------------------------------

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
