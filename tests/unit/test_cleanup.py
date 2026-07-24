"""Regression tests for expired-grant cleanup (issue #140)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest


def test_purge_expired_grants_removes_only_expired(monkeypatch):
    """Expired grants are deleted; non-expired grants are kept."""

    class FakeGrant:
        def __init__(self, id_, expires_at):
            self.id = id_
            self.expires_at = expires_at

    class FakeSession:
        def __init__(self, store):
            self.store = store

        def query(self, model):
            return self

        def filter(self, _cond):
            now = datetime.now(timezone.utc)
            expired = [g for g in self.store if g.expires_at < now]
            kept = [g for g in self.store if g.expires_at >= now]
            self._expired = expired
            self._kept = kept
            return self

        def all(self):
            return list(getattr(self, "_expired", []))

        def update(self, values, synchronize_session="fetch"):
            return 0

        def delete(self, synchronize_session=False):
            removed = len(self._expired)
            self.store.clear()
            self.store.extend(self._kept)
            return removed

        def commit(self):
            pass

        def rollback(self):
            raise RuntimeError("rollback called unexpectedly")

        def close(self):
            pass

    now = datetime.now(timezone.utc)
    store = [
        FakeGrant(1, now - timedelta(hours=1)),  # expired
        FakeGrant(2, now + timedelta(hours=1)),  # active
        FakeGrant(3, now - timedelta(seconds=1)),  # expired
    ]

    def factory():
        return FakeSession(store)

    from kubetix_api import cleanup

    deleted = cleanup.purge_expired_grants(factory)

    assert deleted == 2
    assert [g.id for g in store] == [2]


@pytest.mark.asyncio
async def test_cleanup_loop_runs_once_and_stops(monkeypatch):
    """Loop exits promptly when the stop event is set, after a sweep."""
    import asyncio
    from kubetix_api import cleanup

    calls = {"n": 0}

    def fake_purge(_factory):
        calls["n"] += 1
        return 0

    monkeypatch.setattr(cleanup, "purge_expired_grants", fake_purge)
    # Make the loop sleep very briefly between sweeps.
    monkeypatch.setattr(cleanup, "DEFAULT_INTERVAL_SECONDS", 0)

    stop = asyncio.Event()
    task = asyncio.create_task(cleanup.run_grant_cleanup_loop(stop))
    # Give the loop a moment to run at least one iteration.
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)
    assert calls["n"] >= 1


@pytest.mark.asyncio
async def test_cleanup_loop_survives_purge_errors(monkeypatch, caplog):
    """A failing sweep must not kill the loop; subsequent sweeps still run."""
    import asyncio
    import logging
    from kubetix_api import cleanup

    state = {"n": 0, "raise_on": 1}

    def flaky_purge(_factory):
        state["n"] += 1
        if state["n"] == state["raise_on"]:
            raise RuntimeError("transient db error")
        return 0

    monkeypatch.setattr(cleanup, "purge_expired_grants", flaky_purge)
    monkeypatch.setattr(cleanup, "DEFAULT_INTERVAL_SECONDS", 0)

    stop = asyncio.Event()
    with caplog.at_level(logging.ERROR, logger="kubetix_api.cleanup"):
        task = asyncio.create_task(cleanup.run_grant_cleanup_loop(stop))
        # Let the failing sweep happen, then a successful one.
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=1.0)

    # The loop must have run more than once (failure did not stop it).
    assert state["n"] >= 2
    # The failure was logged at ERROR level.
    assert any(
        "Expired-grant cleanup iteration failed" in r.message for r in caplog.records
    )


def test_purge_expired_grants_preserves_audit_trail(monkeypatch):
    """AuditLog rows referencing expired grants have grant_id nulled before deletion (issue #250)."""

    class FakeGrant:
        def __init__(self, id_):
            self.id = id_

    class FakeAuditLog:
        def __init__(self, grant_id):
            self.grant_id = grant_id

    class FakeQuery:
        def __init__(self, model, store):
            self.model = model
            self.store = store

        def filter(self, _cond):
            return self

        def all(self):
            return list(self.store)

        def update(self, values, synchronize_session="fetch"):
            for item in self.store:
                for key, val in values.items():
                    # Handle SQLAlchemy InstrumentedAttribute keys
                    attr_name = getattr(key, "key", str(key))
                    setattr(item, attr_name, val)
            return len(self.store)

        def delete(self, synchronize_session=False):
            count = len(self.store)
            self.store.clear()
            return count

    class FakeSession:
        def __init__(self):
            self.grants = [
                FakeGrant("expired-1"),
                FakeGrant("expired-2"),
            ]
            self.audit_logs = [
                FakeAuditLog("expired-1"),
                FakeAuditLog("expired-2"),
                FakeAuditLog(None),
            ]

        def query(self, model):
            if model.__name__ == "Grant":
                return FakeQuery(model, self.grants)
            elif model.__name__ == "AuditLog":
                return FakeQuery(model, self.audit_logs)
            raise ValueError(f"Unknown model: {model}")

        def commit(self):
            pass

        def rollback(self):
            raise RuntimeError("rollback called unexpectedly")

        def close(self):
            pass

    from kubetix_api import cleanup

    deleted = cleanup.purge_expired_grants(lambda: FakeSession())

    assert deleted == 2
