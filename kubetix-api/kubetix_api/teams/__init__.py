"""Team management — CRUD operations."""

from typing import List

from fastapi import HTTPException, Depends
from sqlalchemy import and_

from kubetix_api.database import get_db
from kubetix_api.models import Team, TeamMember, User, provision_user
from kubetix_api.schemas import TeamCreate, TeamResponse, TeamMemberCreate, TeamMemberResponse


def _is_team_member(db, team_id: str, user_id: str) -> bool:
    """Check if a user is a member of a team."""
    return db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id,
    ).first() is not None


def _is_team_owner_or_admin(db, team_id: str, user_id: str) -> bool:
    """Check if a user is an owner or admin of a team."""
    member = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id,
    ).first()
    return member is not None and member.role in ("owner", "admin")


def create_team(
    team_data: TeamCreate,
    current_user: User,
    db,
) -> TeamResponse:
    """Create a new team with the creator as owner."""
    new_team = Team(
        id=__import__("secrets").token_urlsafe(16),
        name=team_data.name,
        description=team_data.description,
        created_by=current_user.id,
    )

    db.add(new_team)

    member = TeamMember(
        id=__import__("secrets").token_urlsafe(16),
        team_id=new_team.id,
        user_id=current_user.id,
        role="owner",
    )
    db.add(member)

    db.commit()
    db.refresh(new_team)

    return TeamResponse.model_validate(new_team)


def list_teams(current_user: User, db) -> List[TeamResponse]:
    """List all teams the user is a member of."""
    team_ids = db.query(TeamMember.team_id).filter(
        TeamMember.user_id == current_user.id,
    ).subquery()

    teams = db.query(Team).filter(
        Team.id.in_(team_ids),
    ).order_by(Team.created_at.desc()).all()

    return [TeamResponse.model_validate(t) for t in teams]


def get_team(team_id: str, current_user: User, db) -> TeamResponse:
    """Get a team by ID (user must be a member)."""
    team = db.query(Team).filter(Team.id == team_id).first()

    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    if not _is_team_member(db, team_id, current_user.id):
        raise HTTPException(status_code=403, detail="Not a member of this team")

    return TeamResponse.model_validate(team)


def add_team_member(
    team_id: str,
    member_data: TeamMemberCreate,
    current_user: User,
    db,
) -> TeamMemberResponse:
    """Add a member to a team (owner or admin only)."""
    if not _is_team_owner_or_admin(db, team_id, current_user.id):
        raise HTTPException(
            status_code=403,
            detail="Only team owners and admins can add members",
        )

    target_user = db.query(User).filter(User.email == member_data.email).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    existing = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == target_user.id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="User is already a member of this team",
        )

    new_member = TeamMember(
        id=__import__("secrets").token_urlsafe(16),
        team_id=team_id,
        user_id=target_user.id,
        role=member_data.role,
    )

    db.add(new_member)
    db.commit()
    db.refresh(new_member)

    # Enrich with user data
    return _member_response(db, new_member)


def remove_team_member(team_id: str, user_id: str, current_user: User, db) -> None:
    """Remove a member from a team (owner only)."""
    if not _is_team_owner_or_admin(db, team_id, current_user.id):
        raise HTTPException(
            status_code=403,
            detail="Only team owners can remove members",
        )

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself from the team")

    db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id,
    ).delete()

    db.commit()


def list_team_members(team_id: str, current_user: User, db) -> List[TeamMemberResponse]:
    """List all members of a team (user must be a member)."""
    if not _is_team_member(db, team_id, current_user.id):
        raise HTTPException(status_code=403, detail="Not a member of this team")

    members = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id)
        .join(User, TeamMember.user_id == User.id)
        .all()
    )

    return [_member_response(db, m) for m in members]


def _member_response(db, member: TeamMember) -> TeamMemberResponse:
    """Build a TeamMemberResponse with enriched user data."""
    user = db.query(User).filter(User.id == member.user_id).first()
    return TeamMemberResponse(
        id=member.id,
        user_id=member.user_id,
        email=user.email if user else "",
        full_name=user.full_name if user else None,
        role=member.role,
        joined_at=member.joined_at,
    )
