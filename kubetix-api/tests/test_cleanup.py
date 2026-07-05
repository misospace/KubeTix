"""Regression tests for expired-grant cleanup (issue #140)."""
from unittest.mock import MagicMock

from kubetix_api.cleanup import purge_expired_grants
from kubetix_api.models import Grant


def _make_session_factory(expired_count):
    """Return a session factory whose Grant.query.delete returns ``expired_count``."""
    session = MagicMock()
    session.query.return_value.filter.return_value.delete.return_value = expired_count
    factory = MagicMock(return_value=session)
    return factory, session


def test_purge_deletes_expired_grants_and_commits():
    factory, session = _make_session_factory(expired_count=3)

    deleted = purge_expired_grants(factory)

    assert deleted == 3
    # delete() is called on a Query object filtered by expires_at < now
    session.query.assert_called_once_with(Grant)
    session.query.return_value.filter.assert_called_once()
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_purge_returns_zero_when_no_expired_grants():
    factory, session = _make_session_factory(expired_count=0)

    deleted = purge_expired_grants(factory)

    assert deleted == 0
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_purge_rolls_back_on_error():
    factory, session = _make_session_factory(expired_count=1)
    session.commit.side_effect = RuntimeError("boom")

    import pytest

    with pytest.raises(RuntimeError):
        purge_expired_grants(factory)

    session.rollback.assert_called_once()
    session.close.assert_called_once()