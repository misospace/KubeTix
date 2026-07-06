"""Regression tests for expired-grant cleanup (issue #140)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest


def test_purge_expired_grants_removes_only_expired(monkeypatch):
    """Expired grants are deleted; non-expired grants are kept."""

    class FakeSession:
        def __init__(self, store):
            self.store = store

        def query(self, model):
            return self

        def filter(self, _cond):
            now = datetime.now(timezone.utc)
            kept = [g for g in self.store if g["expires_at"] >= now]
            removed = len(self.store) - len(kept)
            self.store.clear()
            self.store.extend(kept)
            return MagicMock(delete=MagicMock(return_value=removed))

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

    from kubetix_api import cleanup

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
    assert any("Expired-grant cleanup iteration failed" in r.message for r in caplog.records)
