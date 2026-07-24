"""Regression tests for expired-grant cleanup (issue #140)."""

from unittest.mock import MagicMock

from kubetix_api.cleanup import purge_expired_grants
from kubetix_api.models import AuditLog, Grant


def _make_session_factory(expired_count):
    """Return a session factory whose Grant.query.delete returns ``expired_count``."""
    session = MagicMock()
    # When there are expired grants, .all() returns mock grant objects with ids
    if expired_count > 0:
        fake_grants = [MagicMock(id=f"grant-{i}") for i in range(expired_count)]
        session.query.return_value.filter.return_value.all.return_value = fake_grants
        # AuditLog query update returns the number of rows updated
        session.query.return_value.filter.return_value.update.return_value = (
            expired_count
        )
    else:
        session.query.return_value.filter.return_value.all.return_value = []
    session.query.return_value.filter.return_value.delete.return_value = expired_count
    factory = MagicMock(return_value=session)
    return factory, session


def test_purge_deletes_expired_grants_and_commits():
    factory, session = _make_session_factory(expired_count=3)

    deleted = purge_expired_grants(factory)

    assert deleted == 3
    # delete() is called on a Query object filtered by expires_at < now
    session.query.assert_called()
    session.query.return_value.filter.assert_called()
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_purge_returns_zero_when_no_expired_grants():
    factory, session = _make_session_factory(expired_count=0)

    deleted = purge_expired_grants(factory)

    assert deleted == 0
    session.commit.assert_not_called()
    session.close.assert_called_once()


def test_purge_rolls_back_on_error():
    factory, session = _make_session_factory(expired_count=1)
    session.commit.side_effect = RuntimeError("boom")

    import pytest

    with pytest.raises(RuntimeError):
        purge_expired_grants(factory)

    session.rollback.assert_called_once()
    session.close.assert_called_once()


def test_purge_nulls_audit_log_grant_id_before_delete():
    """AuditLog grant_id is nulled before expired grants are deleted (issue #250)."""
    factory, session = _make_session_factory(expired_count=2)

    purge_expired_grants(factory)

    # Verify AuditLog was queried and updated with grant_id=None
    query_calls = session.query.call_args_list
    assert any(
        call[0][0].__name__ == "AuditLog" for call in query_calls
    ), "AuditLog should be queried before deleting grants"
    # The update call should set grant_id to None
    session.query.return_value.filter.return_value.update.assert_called_once()
    update_call = session.query.return_value.filter.return_value.update.call_args
    assert update_call[0][0] == {AuditLog.grant_id: None}
