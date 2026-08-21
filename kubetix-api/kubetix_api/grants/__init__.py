"""Grant management — encryption, CRUD operations."""

import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

from cryptography.fernet import Fernet
from fastapi import HTTPException, Depends, status

from kubetix_api.database import get_db
from kubetix_api.models import Grant, AuditLog, User
from kubetix_api.schemas import GrantCreate, GrantResponse, GrantWithKubeconfig

# ---------------------------------------------------------------------------
# Encryption helper
# ---------------------------------------------------------------------------


def _get_fernet() -> Fernet:
    """Return a Fernet instance.

    Raises ValueError if KUBECONFIG_ENCRYPTION_KEY is not set, because an
    ephemeral key would cause silent data loss on every API restart.
    """
    key = os.environ.get("KUBECONFIG_ENCRYPTION_KEY")
    if not key:
        raise ValueError(
            "KUBECONFIG_ENCRYPTION_KEY must be set; without it encrypted "
            "kubeconfig grants become undecryptable after every restart."
        )
    return Fernet(key.encode())


def _encryption_key_error_response(exc: ValueError) -> HTTPException:
    """Translate a missing/invalid KUBECONFIG_ENCRYPTION_KEY into a clear 503.

    Generates an actionable error message explaining how to fix the issue
    instead of leaking an opaque 500 to operators.
    """
    message = (
        "Server is misconfigured: KUBECONFIG_ENCRYPTION_KEY is not set or is "
        'invalid. Generate a Fernet key with `python -c "from cryptography.fernet '
        'import Fernet; print(Fernet.generate_key().decode())"` and set it via '
        "the kubetix-api-secrets Secret (key: KUBECONFIG_ENCRYPTION_KEY), the "
        "KUBECONFIG_ENCRYPTION_KEY env var, or the bundled docker-compose. "
        f"Underlying error: {exc}"
    )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=message
    )


# ---------------------------------------------------------------------------
# Grant operations
# ---------------------------------------------------------------------------


def list_grants_for_user(
    user: User,
    db,
) -> List[Grant]:
    """List active, non-revoked grants for a user."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (
        db.query(Grant)
        .filter(
            Grant.user_id == user.id,
            Grant.revoked == False,
            Grant.expires_at > now,
        )
        .order_by(Grant.created_at.desc())
        .all()
    )


def create_grant(
    grant_data: GrantCreate,
    current_user: User,
    db,
) -> GrantResponse:
    """Create a new grant with encrypted kubeconfig.

    Only admins can create grants; non-admin users are rejected to prevent
    unprivileged users from obtaining the server's full cluster credentials.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create grants",
        )

    if grant_data.role not in ["view", "edit", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be view, edit, or admin",
        )

    if grant_data.expiry_hours < 1 or grant_data.expiry_hours > 720:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expiry must be between 1 and 720 hours",
        )

    kubeconfig_path = os.environ.get("KUBECONFIG", Path.home() / ".kube" / "config")
    if not os.path.exists(kubeconfig_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Kubeconfig not found at {kubeconfig_path}",
        )

    with open(kubeconfig_path) as f:
        kubeconfig = f.read()

    try:
        fernet = _get_fernet()
    except ValueError as exc:
        raise _encryption_key_error_response(exc) from exc
    encrypted_kubeconfig = fernet.encrypt(kubeconfig.encode()).decode()

    expires_at = datetime.now(timezone.utc) + timedelta(hours=grant_data.expiry_hours)

    new_grant = Grant(
        id=__import__("secrets").token_urlsafe(16),
        user_id=current_user.id,
        cluster_name=grant_data.cluster_name,
        namespace=grant_data.namespace,
        role=grant_data.role,
        encrypted_kubeconfig=encrypted_kubeconfig,
        expires_at=expires_at,
    )

    db.add(new_grant)

    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        grant_id=new_grant.id,
        action="created",
        details=f"Created grant for {grant_data.cluster_name}",
    )
    db.add(audit)
    db.commit()
    db.refresh(new_grant)

    return GrantResponse.model_validate(new_grant)


def get_grant(grant_id: str, current_user: User, db) -> GrantWithKubeconfig:
    """Decrypt and return a grant's kubeconfig."""
    grant = db.query(Grant).filter(Grant.id == grant_id).first()

    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    if grant.user_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this grant"
        )
    if grant.revoked:
        raise HTTPException(status_code=400, detail="Grant has been revoked")

    expires_at = grant.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=400, detail="Grant has expired")

    try:
        fernet = _get_fernet()
    except ValueError as exc:
        raise _encryption_key_error_response(exc) from exc
    kubeconfig = fernet.decrypt(grant.encrypted_kubeconfig.encode()).decode()

    # Log the download event in the audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        grant_id=grant.id,
        action="downloaded",
        details=f"Downloaded kubeconfig for cluster '{grant.cluster_name}'",
    )
    db.add(audit_log)
    db.commit()

    return GrantWithKubeconfig(
        id=grant.id,
        cluster_name=grant.cluster_name,
        namespace=grant.namespace,
        role=grant.role,
        expires_at=grant.expires_at,
        kubeconfig=kubeconfig,
    )


def revoke_grant(grant_id: str, current_user: User, db) -> None:
    """Revoke a grant (owner or admin only)."""
    grant = db.query(Grant).filter(Grant.id == grant_id).first()

    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    if grant.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=403, detail="Not authorized to revoke this grant"
        )

    grant.revoked = True
    db.commit()

    audit = AuditLog(
        user_id=current_user.id,
        grant_id=grant_id,
        action="revoked",
        details="Manually revoked",
    )
    db.add(audit)
    db.commit()


def update_grant(
    grant_id: str,
    payload: dict,
    current_user: User,
    db,
) -> GrantResponse:
    """Upsert/update a grant from the CLI sync bridge.

    Accepts the full payload emitted by ``kc-share.sync_to_api`` (which
    contains fields such as ``id``, ``created_at``, ``expires_at``,
    ``revoked``, ``metadata``, ``encrypted_kubeconfig`` in addition to the
    canonical ``GrantCreate`` fields).  Authorisation matches
    ``revoke_grant``: the grant owner or an admin may write.  Unknown
    fields are ignored so that the bridge can evolve without 422s.

    If the grant does not yet exist (e.g. the CLI created it locally after
    the API restart), a new row is inserted with the supplied id, owning
    user, timestamps, and (re-)encrypted kubeconfig.
    """
    grant = db.query(Grant).filter(Grant.id == grant_id).first()

    if grant is not None:
        if grant.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=403, detail="Not authorized to update this grant"
            )
    else:
        # Upsert path: CLI is the source of truth and the API row was lost.
        # Owner is taken from the payload so existing CLI records import
        # cleanly; admins can adopt orphans via an explicit user_id field.
        new_user_id = current_user.id
        if current_user.is_admin and payload.get("user_id"):
            new_user_id = payload["user_id"]
        grant = Grant(
            id=grant_id,
            user_id=new_user_id,
            cluster_name=payload.get("cluster_name", "unknown"),
            namespace=payload.get("namespace"),
            role=payload.get("role", "view"),
            encrypted_kubeconfig=payload.get("encrypted_kubeconfig") or "",
        )

    # Apply writable fields if present in the payload.
    if "cluster_name" in payload and payload["cluster_name"]:
        grant.cluster_name = payload["cluster_name"]
    if "namespace" in payload:
        grant.namespace = payload["namespace"]
    if "role" in payload and payload["role"]:
        grant.role = payload["role"]
    if "revoked" in payload:
        grant.revoked = bool(payload["revoked"])
    if "encrypted_kubeconfig" in payload and payload["encrypted_kubeconfig"]:
        grant.encrypted_kubeconfig = payload["encrypted_kubeconfig"]

    expires_at_raw = payload.get("expires_at")
    if expires_at_raw:
        try:
            parsed = datetime.fromisoformat(str(expires_at_raw).replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            grant.expires_at = parsed
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid expires_at value: {expires_at_raw!r}",
            )

    if not grant.expires_at:
        grant.expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    if grant not in db.new:
        db.add(grant)

    audit = AuditLog(
        user_id=current_user.id,
        grant_id=grant.id,
        action="synced",
        details=f"Synced grant for {grant.cluster_name} from CLI",
    )
    db.add(audit)
    db.commit()
    db.refresh(grant)

    return GrantResponse.model_validate(grant)


def get_audit_log(db, current_user: User) -> List[dict]:
    """Get audit log entries (admins see all, users see their own)."""
    if current_user.is_admin:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    else:
        logs = (
            db.query(AuditLog)
            .filter(
                AuditLog.user_id == current_user.id,
            )
            .order_by(AuditLog.created_at.desc())
            .limit(100)
            .all()
        )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "grant_id": log.grant_id,
            "action": log.action,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]
