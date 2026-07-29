"""
Unit tests for KubeTix API - Teams
Tests the team management endpoints
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from _shared_db import engine, TestingSessionLocal
import secrets
from datetime import datetime, timezone, timedelta

# Import the main app
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, Team, TeamMember, get_password_hash

# Test database


class TestCreateTeam:
    """Tests for creating teams."""

    def test_create_team_success(self, client, auth_headers):
        """Test creating a new team."""
        response = client.post(
            "api/v1/teams",
            json={"name": "test-team", "description": "A test team"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-team"
        assert data["description"] == "A test team"
        assert "id" in data
        assert "created_at" in data

    def test_create_team_minimal(self, client, auth_headers):
        """Test creating a team with minimal data."""
        response = client.post(
            "api/v1/teams", json={"name": "minimal-team"}, headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "minimal-team"

    def test_create_team_without_name(self, client, auth_headers):
        """Test creating a team without name fails."""
        response = client.post(
            "api/v1/teams", json={"description": "No name team"}, headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_team_invalid_name(self, client, auth_headers):
        """Test creating a team with invalid name (spaces/uppercase) fails."""
        response = client.post(
            "api/v1/teams", json={"name": "Invalid Team Name"}, headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_team_unauthorized(self, client):
        """Test creating a team without authentication."""
        response = client.post("api/v1/teams", json={"name": "test-team"})
        assert response.status_code == 401


class TestListTeams:
    """Tests for listing teams."""

    def test_list_teams_empty(self, client, auth_headers):
        """Test listing teams when none exist."""
        response = client.get("api/v1/teams", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    def test_list_teams_with_data(self, client, db_session, auth_headers, auth_token):
        """Test listing teams."""
        # Create user
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        # Create team
        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        # Add user as owner
        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        # List teams
        response = client.get("api/v1/teams", headers=auth_headers)
        assert response.status_code == 200
        teams = response.json()
        assert len(teams) == 1
        assert teams[0]["name"] == "test-team"

    def test_list_teams_not_member(self, client, db_session, auth_headers):
        """Test that teams where user is not a member are not listed."""
        # Create different user and team
        other_user = User(
            id=secrets.token_urlsafe(16),
            email="other@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(other_user)

        team = Team(
            id=secrets.token_urlsafe(16), name="other-team", created_by=other_user.id
        )
        db_session.add(team)
        db_session.commit()

        # List teams - should be empty for our user
        response = client.get("api/v1/teams", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []


class TestGetTeam:
    """Tests for getting a specific team."""

    def test_get_team_success(self, client, db_session, auth_headers, auth_token):
        """Test getting a team the user is a member of."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        response = client.get(f"api/v1/teams/{team.id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["name"] == "test-team"

    def test_get_team_not_member(self, client, db_session, auth_headers):
        """Test getting a team the user is not a member of."""
        other_user = User(
            id=secrets.token_urlsafe(16),
            email="other@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(other_user)

        team = Team(
            id=secrets.token_urlsafe(16), name="private-team", created_by=other_user.id
        )
        db_session.add(team)
        db_session.commit()

        response = client.get(f"api/v1/teams/{team.id}", headers=auth_headers)
        assert response.status_code == 403

    def test_get_team_not_found(self, client, auth_headers):
        """Test getting a nonexistent team."""
        response = client.get("api/v1/teams/nonexistent-id", headers=auth_headers)
        assert response.status_code == 404


class TestAddTeamMember:
    """Tests for adding team members."""

    def test_add_member_success(self, client, db_session, auth_headers, auth_token):
        """Test adding a member to a team."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        # Create team
        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        # Add user as owner
        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)

        # Create another user to add
        new_user = User(
            id=secrets.token_urlsafe(16),
            email="newuser@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(new_user)
        db_session.commit()

        # Add member
        response = client.post(
            f"api/v1/teams/{team.id}/members",
            json={"email": "newuser@example.com", "role": "member"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_add_member_not_owner(self, client, db_session, auth_headers, auth_token):
        """Test that non-owners cannot add members."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        # Create team
        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        # Add user as member (not owner)
        member = TeamMember(
            id=secrets.token_urlsafe(16),
            team_id=team.id,
            user_id=user.id,
            role="member",
        )
        db_session.add(member)
        db_session.commit()

        # Try to add member - should fail
        response = client.post(
            f"api/v1/teams/{team.id}/members",
            json={"email": "newuser@example.com", "role": "member"},
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_add_member_nonexistent_user(
        self, client, db_session, auth_headers, auth_token
    ):
        """Test adding a nonexistent user."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        response = client.post(
            f"api/v1/teams/{team.id}/members",
            json={"email": "nonexistent@example.com", "role": "member"},
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_add_member_already_member(
        self, client, db_session, auth_headers, auth_token
    ):
        """Test adding someone who's already a member."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        # Try to add owner again
        response = client.post(
            f"api/v1/teams/{team.id}/members",
            json={"email": "test@example.com", "role": "member"},
            headers=auth_headers,
        )
        assert response.status_code == 400


class TestRemoveTeamMember:
    """Tests for removing team members."""

    def test_remove_member_success(self, client, db_session, auth_headers, auth_token):
        """Test removing a member from a team."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        # Create team
        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        # Add user as owner
        owner_member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(owner_member)

        # Create member to remove
        member_user = User(
            id=secrets.token_urlsafe(16),
            email="member@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(member_user)

        member = TeamMember(
            id=secrets.token_urlsafe(16),
            team_id=team.id,
            user_id=member_user.id,
            role="member",
        )
        db_session.add(member)
        db_session.commit()
        member_user_id = member_user.id

        # Remove member
        response = client.delete(
            f"api/v1/teams/{team.id}/members/{member_user_id}", headers=auth_headers
        )
        assert response.status_code == 204

    def test_remove_self_not_allowed(
        self, client, db_session, auth_headers, auth_token
    ):
        """Test that owners cannot remove themselves."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        # Try to remove self
        response = client.delete(
            f"api/v1/teams/{team.id}/members/{user.id}", headers=auth_headers
        )
        assert response.status_code == 400

    def test_remove_non_member(self, client, db_session, auth_headers, auth_token):
        """Test removing someone who's not a member."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        response = client.delete(
            f"api/v1/teams/{team.id}/members/nonexistent-id", headers=auth_headers
        )
        assert response.status_code in [204, 404]


class TestListTeamMembers:
    """Tests for listing team members."""

    def test_list_members_success(self, client, db_session, auth_headers, auth_token):
        """Test listing team members."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        team = Team(id=secrets.token_urlsafe(16), name="test-team", created_by=user.id)
        db_session.add(team)

        member = TeamMember(
            id=secrets.token_urlsafe(16), team_id=team.id, user_id=user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        response = client.get(f"api/v1/teams/{team.id}/members", headers=auth_headers)
        assert response.status_code == 200
        members = response.json()
        assert len(members) == 1
        assert members[0]["role"] == "owner"

    def test_list_members_not_member(self, client, db_session, auth_headers):
        """Test listing members when not a team member."""
        other_user = User(
            id=secrets.token_urlsafe(16),
            email="other@example.com",
            hashed_password=get_password_hash("testpassword123"),
        )
        db_session.add(other_user)

        team = Team(
            id=secrets.token_urlsafe(16), name="private-team", created_by=other_user.id
        )
        db_session.add(team)
        db_session.commit()

        response = client.get(f"api/v1/teams/{team.id}/members", headers=auth_headers)
        assert response.status_code == 403


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
