"""Regression test for issue #313: API returns naive UTC datetimes.

All DateTime columns must be declared with ``timezone=True`` so that the API
serializes timestamps with an explicit timezone offset (e.g. ``+00:00`` or
trailing ``Z``). Without this, the web UI parses them as local time via
``new Date()``, corrupting grant expiry display for users outside UTC.
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime, timezone, timedelta

# ISO 8601 pattern that requires a timezone offset (+HH:MM or Z).
_ISO_TZ_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)$"
)


def _has_tz_offset(value: str) -> bool:
    """Return True if *value* contains an ISO 8601 timezone offset."""
    return _ISO_TZ_PATTERN.search(value) is not None


def test_grant_expires_at_has_utc_offset():
    """GrantResponse serializes expires_at with a UTC offset."""
    from kubetix_api.database import SessionLocal
    from kubetix_api.models import Grant, User, Team
    from kubetix_api.schemas import GrantResponse
    from kubetix_api.auth import get_password_hash

    db = SessionLocal()
    try:
        user = User(
            email="tz-grant@example.com",
            hashed_password=get_password_hash("hunter2!!"),
        )
        db.add(user)
        db.flush()

        team = Team(name="tz-team-grant", created_by=user.id)
        db.add(team)
        db.flush()

        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        grant = Grant(
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="admin",
            encrypted_kubeconfig="encrypted-data",
            expires_at=expires_at,
        )
        db.add(grant)
        db.commit()

        queried_grant = db.query(Grant).filter(Grant.id == grant.id).first()
        grant_response = GrantResponse.model_validate(queried_grant)

        expires_at_str = grant_response.expires_at.isoformat()
        assert _has_tz_offset(
            expires_at_str
        ), f"expires_at should include a UTC offset (+00:00 or Z), got: {expires_at_str!r}"
    finally:
        db.close()


def test_user_created_at_has_utc_offset():
    """UserResponse serializes created_at with a UTC offset."""
    from kubetix_api.database import SessionLocal
    from kubetix_api.models import User
    from kubetix_api.schemas import UserResponse
    from kubetix_api.auth import get_password_hash

    db = SessionLocal()
    try:
        user = User(
            email="tz-user@example.com",
            hashed_password=get_password_hash("hunter2!!"),
        )
        db.add(user)
        db.commit()

        queried_user = db.query(User).filter(User.id == user.id).first()
        user_response = UserResponse.model_validate(queried_user)

        created_at_str = user_response.created_at.isoformat()
        assert _has_tz_offset(
            created_at_str
        ), f"created_at should include a UTC offset (+00:00 or Z), got: {created_at_str!r}"
    finally:
        db.close()


def test_grant_datetime_columns_are_tz_aware():
    """DateTime columns with TZDateTime return tz-aware values from SQLite."""
    from kubetix_api.database import SessionLocal
    from kubetix_api.models import Grant, User, Team
    from kubetix_api.auth import get_password_hash

    db = SessionLocal()
    try:
        user = User(
            email="tz-raw@example.com",
            hashed_password=get_password_hash("hunter2!!"),
        )
        db.add(user)
        db.flush()

        team = Team(name="tz-team-raw", created_by=user.id)
        db.add(team)
        db.flush()

        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        grant = Grant(
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="admin",
            encrypted_kubeconfig="encrypted-data",
            expires_at=expires_at,
        )
        db.add(grant)
        db.commit()

        queried_grant = db.query(Grant).filter(Grant.id == grant.id).first()

        # Check that expires_at is timezone-aware
        assert (
            queried_grant.expires_at.tzinfo is not None
        ), f"expires_at should be timezone-aware, got: {queried_grant.expires_at!r}"

        # Check that created_at is timezone-aware
        assert (
            queried_grant.created_at.tzinfo is not None
        ), f"created_at should be timezone-aware, got: {queried_grant.created_at!r}"
    finally:
        db.close()
