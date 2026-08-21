"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-21 00:00:00

Captures the full schema defined in ``kubetix_api/models.py`` at the moment
the Alembic framework was adopted. Every model table is created in
dependency order so subsequent autogenerate revisions start from a clean
baseline matching the current ORM models:

* ``users`` (no FKs)
* ``teams`` (FK -> users)
* ``team_members`` (FK -> teams, FK -> users)
* ``grants`` (FK -> users)
* ``audit_log`` (FK -> users, FK -> grants)
* ``auth_codes`` (no FKs — standalone PKCE state)
* ``blacklisted_tokens`` (no FKs)
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    def _now_default() -> sa.sql.functions.GenericFunction:
        # SQLite needs an explicit SQL callable for server-side defaults; using
        # ``CURRENT_TIMESTAMP`` keeps the column behavior identical to the ORM
        # Python-side ``datetime.now`` for downstream queries.
        return sa.func.current_timestamp()

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=True),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sso_provider", sa.String(length=50), nullable=True),
        sa.Column("sso_id", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "teams",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name="fk_teams_created_by_users"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "team_members",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("team_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column(
            "joined_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(
            ["team_id"], ["teams.id"], name="fk_team_members_team_id_teams"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_team_members_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_user"),
    )

    op.create_table(
        "grants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("cluster_name", sa.String(length=255), nullable=False),
        sa.Column("namespace", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("encrypted_kubeconfig", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_grants_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("grant_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_audit_log_user_id_users"
        ),
        sa.ForeignKeyConstraint(
            ["grant_id"], ["grants.id"], name="fk_audit_log_grant_id_grants"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "auth_codes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("code_challenge", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "blacklisted_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("jti", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jti", name="uq_blacklisted_tokens_jti"),
    )
    op.create_index(
        "ix_blacklisted_tokens_jti",
        "blacklisted_tokens",
        ["jti"],
        unique=True,
    )


def downgrade() -> None:
    # Drop in reverse dependency order so FK constraints don't block teardown.
    op.drop_index("ix_blacklisted_tokens_jti", table_name="blacklisted_tokens")
    op.drop_table("blacklisted_tokens")

    op.drop_table("auth_codes")

    op.drop_table("audit_log")
    op.drop_table("grants")

    op.drop_table("team_members")
    op.drop_table("teams")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
