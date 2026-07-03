"""Regression test: verify foreign key constraints are defined on models.

Fixes #139 – Missing foreign key constraints.
"""

from kubetix_api.models import (
    AuditLog,
    Grant,
    Team,
    TeamMember,
)


def _fk_columns(model):
    """Return dict of column_name -> ForeignKey constraint for a model."""
    result = {}
    for col in model.__table__.columns:
        fks = list(col.foreign_keys)
        if fks:
            result[col.name] = str(fks[0])
    return result


class TestTeamFKs:
    def test_created_by_references_users(self):
        fks = _fk_columns(Team)
        assert "created_by" in fks, "Team.created_by must have a ForeignKey"
        assert "users.id" in fks["created_by"]


class TestTeamMemberFKs:
    def test_team_id_references_teams(self):
        fks = _fk_columns(TeamMember)
        assert "team_id" in fks, "TeamMember.team_id must have a ForeignKey"
        assert "teams.id" in fks["team_id"]

    def test_user_id_references_users(self):
        fks = _fk_columns(TeamMember)
        assert "user_id" in fks, "TeamMember.user_id must have a ForeignKey"
        assert "users.id" in fks["user_id"]


class TestGrantFKs:
    def test_user_id_references_users(self):
        fks = _fk_columns(Grant)
        assert "user_id" in fks, "Grant.user_id must have a ForeignKey"
        assert "users.id" in fks["user_id"]


class TestAuditLogFKs:
    def test_user_id_references_users(self):
        fks = _fk_columns(AuditLog)
        assert "user_id" in fks, "AuditLog.user_id must have a ForeignKey"
        assert "users.id" in fks["user_id"]

    def test_grant_id_references_grants(self):
        fks = _fk_columns(AuditLog)
        assert "grant_id" in fks, "AuditLog.grant_id must have a ForeignKey"
        assert "grants.id" in fks["grant_id"]
