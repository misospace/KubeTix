"""Regression tests for expired-grant cleanup (issue #140)."""

from datetime import datetime, timedelta, timezone

import pytest


def test_purge_expired_grants_removes_only_expired(monkeypatch):
    """Expired grants are deleted; non-expired grants are kept."""
    # Use an in-memory fake to avoid touching the real DB.
    class FakeQuery:
        def __init__(self, store):
            self.store = store

        def filter(self, _cond):
            return self

        def delete(self, synchronize_session=False):
            now = datetime.now(timezone.utc)
            kept = [g for g in self.store if g["expires_at"] >= now]
            removed = len(self.store) - len(kept)
            self.store.clear()
            self.store.extend(kept)
            return removed

    class FakeSession:
        def __init__(self, store):
            self.store = store

        def query(self, _model):
            return FakeQuery(self.store)

        def commit(self):
            pass

        def rollback(self):
            raise RuntimeError("rollback called unexpectedly")

        def close(self):
            pass

    now = datetime.now(timezone.utc)
    store = [
        {"id": 1, "expires_at": now - timedelta(hours=1)},   # expired
        {"id": 2, "expires_at": now + timedelta(hours=1)},   # active
        {"id": 3, "expires_at": now - timedelta(seconds=1)},  # expired
    ]

    def factory():
        return FakeSession(store)

    # Import after the fake is set up so the model lookup resolves.
    from kubetix_api import cleanup

    # Monkeypatch the Grant symbol the cleanup module imports lazily.
    class _Grant:
        pass

    monkeypatch.setattr(cleanup, "Grant", _Grant, raising=False)
    # The cleanup module does `from kubetix_api.models import Grant` lazily;
    # ensure that name resolves to our stand-in as well.
    import kubetix_api.models as _models
    monkeypatch.setattr(_models, "Grant", _Grant, raising=False)

    deleted = cleanup.purge_expired_grants(factory)
    assert deleted == 2
    assert [g["id"] for g in store] == [2]


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