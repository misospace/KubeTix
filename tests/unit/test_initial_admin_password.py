"""Regression tests for startup handling of the initial admin password."""

import asyncio
import os

import main
from kubetix_api import cleanup, database


def test_initial_admin_password_is_removed_after_startup(monkeypatch):
    """The bootstrap password must not remain in the process environment."""
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "bootstrap-secret")
    monkeypatch.setenv("TESTING", "1")

    class ExistingAdminQuery:
        def filter(self, _condition):
            return self

        def first(self):
            return object()

    class FakeSession:
        def query(self, _model):
            return ExistingAdminQuery()

        def close(self):
            pass

    session = FakeSession()
    monkeypatch.setattr(database, "SessionLocal", lambda: session)

    async def fake_cleanup_loop(stop_event):
        await stop_event.wait()

    monkeypatch.setattr(cleanup, "run_grant_cleanup_loop", fake_cleanup_loop)

    async def run_lifespan():
        async with main.lifespan(main.app):
            assert "INITIAL_ADMIN_PASSWORD" not in os.environ

    asyncio.run(run_lifespan())
    assert "INITIAL_ADMIN_PASSWORD" not in os.environ
