"""Background cleanup tasks for KubeTix.

Provides a periodic sweeper that removes expired grants so the database
does not grow unbounded. Invoked from the FastAPI lifespan handler.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from kubetix_api.database import SessionLocal
from kubetix_api.models import AuditLog, Grant

log = logging.getLogger(__name__)

# Sweep every 1 hour by default. Override via GRANT_CLEANUP_INTERVAL_SECONDS.
DEFAULT_INTERVAL_SECONDS = 3600


async def run_grant_cleanup_loop(stop_event: asyncio.Event) -> None:
    """Periodically delete expired grants until ``stop_event`` is set.

    Intended to be launched as an asyncio task from the FastAPI lifespan.
    """
    interval = int(
        os.environ.get("GRANT_CLEANUP_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)
    )

    log.info("Expired-grant cleanup loop starting (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            deleted = purge_expired_grants(SessionLocal)
            if deleted:
                log.info("Expired-grant cleanup removed %s grant(s)", deleted)
        except Exception:  # pragma: no cover - defensive logging
            log.exception("Expired-grant cleanup iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
    log.info("Expired-grant cleanup loop stopped")


def purge_expired_grants(session_factory=SessionLocal) -> int:
    """Delete grants whose ``expires_at`` is in the past.

    Before deleting, null out grant_id on any AuditLog rows that reference the
    expired grants so the forensic audit trail is preserved (soft-reference).

    Returns the number of rows removed. ``session_factory`` is a callable
    that returns a SQLAlchemy ``Session`` (defaults to ``SessionLocal``).
    """
    db: Session = session_factory()
    try:
        now = datetime.now(timezone.utc)
        expired_grants = db.query(Grant).filter(Grant.expires_at < now).all()
        if not expired_grants:
            return 0
        expired_ids = [g.id for g in expired_grants]
        # Preserve audit trail: null out grant_id references before deleting grants
        db.query(AuditLog).filter(AuditLog.grant_id.in_(expired_ids)).update(
            {AuditLog.grant_id: None}, synchronize_session="fetch"
        )
        deleted = (
            db.query(Grant)
            .filter(Grant.expires_at < now)
            .delete(synchronize_session=False)
        )
        db.commit()
        return int(deleted)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
